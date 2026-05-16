from __future__ import annotations

from pydantic import BaseModel, Field


class NetworkFlow(BaseModel):
    device_id: str = Field(..., description="IoT device identifier")
    ts: float | None = None
    proto: str = "tcp"
    service: str = "-"
    duration: float | None = None
    orig_bytes: float | None = 0
    resp_bytes: float | None = 0
    missed_bytes: float | None = 0
    orig_pkts: float | None = 0
    orig_ip_bytes: float | None = 0
    resp_pkts: float | None = 0
    resp_ip_bytes: float | None = 0
    id_orig_p: int | None = Field(None, alias="id.orig_p")
    id_resp_p: int | None = Field(None, alias="id.resp_p")
    conn_state: str = "S0"
    id_resp_h: str | None = Field(None, alias="id.resp_h")

    model_config = {"populate_by_name": True}

    def to_feature_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "ts": self.ts,
            "proto": self.proto,
            "service": self.service,
            "duration": self.duration,
            "orig_bytes": self.orig_bytes,
            "resp_bytes": self.resp_bytes,
            "missed_bytes": self.missed_bytes,
            "orig_pkts": self.orig_pkts,
            "orig_ip_bytes": self.orig_ip_bytes,
            "resp_pkts": self.resp_pkts,
            "resp_ip_bytes": self.resp_ip_bytes,
            "id.orig_p": self.id_orig_p,
            "id.resp_p": self.id_resp_p,
            "conn_state": self.conn_state,
            "id.resp_h": self.id_resp_h,
        }


class PredictRequest(BaseModel):
    flows: list[NetworkFlow]


class DetectionEvent(BaseModel):
    id: str
    device_id: str
    ts: float | None
    prediction: str
    label_code: int
    probability_malicious: float
    probability_benign: float
    received_at: str
    proto: str | None = None
    id_resp_h: str | None = Field(None, alias="id.resp_h")

    model_config = {"populate_by_name": True}


class StatsResponse(BaseModel):
    total: int
    benign: int
    malicious: int
    devices: int
    model_path: str
