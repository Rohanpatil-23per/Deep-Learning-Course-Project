"""Build local, runtime-compatible IMMUNEX Layer 1 and Layer 2 artefacts.

This intentionally uses the labelled CICIDS2017 and UNSW-NB15 datasets that
ship with this project.  It does not download a foundation model or claim a
RoBERTa checkpoint was trained.  The produced models are CPU compatible.
"""
from __future__ import annotations

import json
import pickle
from pathlib import Path

import faiss
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).parent
RNG = np.random.default_rng(42)


def numerical_frame(frame: pd.DataFrame, columns=None):
    if columns is None:
        columns = [c for c in frame.columns if pd.api.types.is_numeric_dtype(frame[c])]
    values = frame.reindex(columns=columns).apply(pd.to_numeric, errors="coerce")
    values = values.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return values, columns


def train_layer1():
    files = sorted((ROOT / "datasets" / "cicids2017").glob("*.parquet"))
    if not files:
        raise RuntimeError("CICIDS2017 parquet files were not found")
    frames = []
    shared = None
    for file in files:
        frame = pd.read_parquet(file)
        numeric, columns = numerical_frame(frame)
        shared = columns if shared is None else [c for c in shared if c in columns]
        numeric["_label"] = 0 if "benign" in file.name.lower() else 1
        frames.append(numeric)
        print(f"L1 read {file.name}: {len(numeric):,} flows")
    frames = [f.reindex(columns=shared + ["_label"]).fillna(0.0) for f in frames]
    data = pd.concat(frames, ignore_index=True)
    # Keep the first 77 consistent CICIDS numerical fields expected by L1.
    columns = shared[:77]
    benign = data[data._label == 0][columns]
    if benign.empty:
        raise RuntimeError("No benign CICIDS baseline was found")
    benign = benign.sample(min(30000, len(benign)), random_state=42)
    scaler = StandardScaler().fit(benign)
    normal = scaler.transform(benign).astype(np.float32)
    forest = IsolationForest(n_estimators=250, contamination="auto", random_state=42, n_jobs=-1).fit(normal)
    scores = forest.decision_function(normal)
    # Below this fifth-percentile normal score is anomalous.
    threshold = float(np.percentile(scores, 5))

    models = ROOT / "models"; models.mkdir(exist_ok=True)
    with (models / "isolation_forest.pkl").open("wb") as f: pickle.dump(forest, f)
    with (models / "layer1_scaler.pkl").open("wb") as f: pickle.dump(scaler, f)
    # A FAISS normal-behaviour index over standardized 77-D data padded to the
    # original 768-D embedding interface.
    vectors = np.zeros((len(normal), 768), dtype=np.float32); vectors[:, :77] = normal
    faiss.normalize_L2(vectors)
    index = faiss.IndexFlatL2(768); index.add(vectors)
    faiss.write_index(index, str(models / "faiss_index.bin"))
    info = {"source": "CICIDS2017", "features": columns, "normal_rows": int(len(normal)),
            "isolation_forest_threshold": threshold, "faiss_dimension": 768}
    (models / "layer1_training.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    print(f"L1 complete: {len(normal):,} normal flows, IF threshold {threshold:.5f}")


def train_layer2():
    # Delay the PyTorch imports.  This lets Layer 1 train on installations
    # where PyTorch and FAISS ship distinct OpenMP runtimes.
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch.utils.data import DataLoader, TensorDataset
    from torch_geometric.data import Data
    from torch_geometric.loader import DataLoader as GraphLoader
    from torch_geometric.nn import GATv2Conv, global_mean_pool
    torch.manual_seed(42)

    class GAT(nn.Module):
        def __init__(self):
            super().__init__(); h, heads = 128, 4
            self.conv1 = GATv2Conv(6, h, heads=heads, edge_dim=1, concat=True)
            self.conv2 = GATv2Conv(h * heads, h, heads=heads, edge_dim=1, concat=True)
            self.conv3 = GATv2Conv(h * heads, h, heads=heads, edge_dim=1, concat=True)
            self.conv4 = GATv2Conv(h * heads, h, heads=1, edge_dim=1, concat=False)
            self.skip_proj = nn.Linear(h * heads, h * heads)
            self.bn1, self.bn2, self.bn3 = nn.BatchNorm1d(h * heads), nn.BatchNorm1d(h * heads), nn.BatchNorm1d(h * heads)
            self.dropout_p = .3
            self.classifier = nn.Sequential(nn.Linear(h,128),nn.ReLU(),nn.Dropout(.3),nn.Linear(128,64),nn.ReLU(),nn.Dropout(.3),nn.Linear(64,1),nn.Sigmoid())
        def forward(self, x, edge_index, edge_attr, batch):
            x1=F.dropout(F.elu(self.bn1(self.conv1(x,edge_index,edge_attr))),p=self.dropout_p,training=self.training)
            x2=F.dropout(F.elu(self.bn2(self.conv2(x1,edge_index,edge_attr))),p=self.dropout_p,training=self.training)
            x3=F.dropout(F.elu(self.bn3(self.conv3(x2,edge_index,edge_attr)+self.skip_proj(x1))),p=self.dropout_p,training=self.training)
            return self.classifier(global_mean_pool(self.conv4(x3,edge_index,edge_attr),batch))

    class BiLSTM(nn.Module):
        def __init__(self):
            super().__init__(); self.lstm=nn.LSTM(6,128,2,batch_first=True,bidirectional=True,dropout=.3); self.bn=nn.BatchNorm1d(256)
            self.stage_classifier=nn.Sequential(nn.Linear(256,128),nn.ReLU(),nn.Dropout(.3),nn.Linear(128,7))
            self.next_stage_head=nn.Sequential(nn.Linear(256,128),nn.ReLU(),nn.Dropout(.3),nn.Linear(128,7))
        def forward(self,x):
            out,_=self.lstm(x); last=self.bn(out[:,-1,:]); return self.stage_classifier(last),self.next_stage_head(last)


def stage_ids(categories: pd.Series):
    mapping = {"normal":0,"reconnaissance":1,"fuzzers":1,"analysis":1,"exploits":2,"shellcode":2,
               "backdoor":3,"worms":3,"generic":4,"dos":4,"infiltration":5,"theft":5}
    return categories.astype(str).str.lower().map(mapping).fillna(2).astype("int64").to_numpy()


    path = ROOT / "datasets" / "unsw_nb15" / "UNSW_NB15_training-set.csv"
    frame = pd.read_csv(path)
    columns = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate"]
    raw = frame[columns].apply(pd.to_numeric, errors="coerce").replace([np.inf,-np.inf],np.nan).fillna(0).to_numpy(dtype=np.float32)
    raw = np.log1p(np.maximum(raw, 0))
    labels = stage_ids(frame["attack_cat"])
    # Retain a balanced, bounded sample so the local CPU training remains practical.
    selected=[]
    for label in range(7):
        ids=np.where(labels==label)[0]
        if len(ids): selected.extend(RNG.choice(ids, min(2500,len(ids)), replace=False))
    selected=np.asarray(selected); RNG.shuffle(selected)
    raw, labels = raw[selected], labels[selected]
    scaler=StandardScaler().fit(raw); x=scaler.transform(raw).astype(np.float32)
    out=ROOT/"layer2_correlation"/"models"; (out/"gatv2").mkdir(parents=True,exist_ok=True); (out/"bilstm").mkdir(parents=True,exist_ok=True)
    with (out/"bilstm"/"scaler.pkl").open("wb") as f: pickle.dump(scaler,f)

    # BiLSTM sees consecutive events; the next-stage label follows the project kill-chain ordering.
    next_map=np.array([1,2,3,5,5,5,3],dtype=np.int64); seq=8
    usable=(len(x)//seq)*seq; xs=x[:usable].reshape(-1,seq,6); ys=labels[:usable].reshape(-1,seq)[:,-1]
    data=DataLoader(TensorDataset(torch.tensor(xs),torch.tensor(ys),torch.tensor(next_map[ys])),batch_size=96,shuffle=True)
    bilstm=BiLSTM(); opt=torch.optim.AdamW(bilstm.parameters(),lr=8e-4,weight_decay=1e-4)
    for epoch in range(5):
        bilstm.train(); loss_sum=0
        for bx,by,bn in data:
            a,b=bilstm(bx); loss=F.cross_entropy(a,by)+.5*F.cross_entropy(b,bn); opt.zero_grad(); loss.backward(); opt.step(); loss_sum+=loss.item()
        print(f"L2 BiLSTM epoch {epoch+1}/5 loss={loss_sum/len(data):.4f}")
    torch.save(bilstm.state_dict(),out/"bilstm"/"best_model.pt")

    # The GAT receives a three-node flow graph (source, flow, destination).
    edge_index=torch.tensor([[0,1,1,2,0,2],[1,0,2,1,2,0]],dtype=torch.long); edge_attr=torch.ones((6,1),dtype=torch.float32)
    graphs=[]
    for row,label in zip(x,labels):
        nodes=torch.tensor(np.vstack((row,row,row)),dtype=torch.float32)
        graphs.append(Data(x=nodes,edge_index=edge_index,edge_attr=edge_attr,y=torch.tensor([float(label!=0)])))
    loader=GraphLoader(graphs,batch_size=64,shuffle=True); gat=GAT(); opt=torch.optim.AdamW(gat.parameters(),lr=8e-4,weight_decay=1e-4)
    for epoch in range(4):
        gat.train(); loss_sum=0
        for batch in loader:
            output=gat(batch.x,batch.edge_index,batch.edge_attr,batch.batch).view(-1); loss=F.binary_cross_entropy(output,batch.y.float().view(-1)); opt.zero_grad(); loss.backward(); opt.step(); loss_sum+=loss.item()
        print(f"L2 GAT epoch {epoch+1}/4 loss={loss_sum/len(loader):.4f}")
    torch.save(gat.state_dict(),out/"gatv2"/"best_model.pt")
    (out/"training.json").write_text(json.dumps({"source":"UNSW-NB15","rows":int(len(x)),"features":columns,"classes":7},indent=2),encoding="utf-8")
    print(f"L2 complete: {len(x):,} UNSW-NB15 flows")


if __name__ == "__main__":
    train_layer1(); train_layer2()
