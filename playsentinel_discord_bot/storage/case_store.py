
from __future__ import annotations

import csv
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


class CaseStore:
    def __init__(self, file_path: str = "flagged_cases.jsonl"):
        self.file_path = Path(file_path)
        self.file_path.touch(exist_ok=True)

    def save_case(self, case_data: dict) -> str:
        case_id = str(uuid.uuid4())[:8]
        record = {
            "case_id": case_id,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "review_status": "unreviewed",
            "reviewed_at": None,
            "reviewed_by": None,
            **case_data,
        }
        with self.file_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(record, ensure_ascii=False) + "\n")
        return case_id

    def review_case(self, case_id: str, verdict: str, reviewed_by: str) -> bool:
        valid_verdicts = {"true_positive", "false_positive", "unsure"}
        if verdict not in valid_verdicts:
            return False

        found = False
        records = []

        with self.file_path.open("r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if record.get("case_id") == case_id:
                    record["review_status"] = verdict
                    record["reviewed_at"] = datetime.now(timezone.utc).isoformat()
                    record["reviewed_by"] = reviewed_by
                    found = True
                records.append(record)

        if not found:
            return False

        temp_path = self.file_path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as file:
            for record in records:
                file.write(json.dumps(record, ensure_ascii=False) + "\n")
        temp_path.replace(self.file_path)

        return True

    def export_training_data(self, format: str = "jsonl") -> tuple[str, int]:
        format = format.lower()
        reviewed_rows = []

        with self.file_path.open("r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                verdict = record.get("review_status", "unreviewed")
                if verdict not in {"true_positive", "false_positive", "unsure"}:
                    continue

                result = record.get("result", {})
                reviewed_rows.append({
                    "case_id": record.get("case_id", ""),
                    "verdict": verdict,
                    "message": record.get("message_content", ""),
                    "category": result.get("category", ""),
                    "stage": result.get("stage", ""),
                    "signals": result.get("signals", []),
                    "score": result.get("score", 0),
                    "conversation_risk": record.get("conversation_risk", 0),
                    "target_id": record.get("target_id", ""),
                    "author_id": record.get("author_id", ""),
                })

        stem = self.file_path.with_suffix("")
        output_path = f"{stem}_training.{format}"

        if format == "jsonl":
            with open(output_path, "w", encoding="utf-8") as file:
                for row in reviewed_rows:
                    file.write(json.dumps(row, ensure_ascii=False) + "\n")
        elif format == "csv":
            with open(output_path, "w", encoding="utf-8", newline="") as file:
                writer = csv.DictWriter(
                    file,
                    fieldnames=[
                        "case_id",
                        "verdict",
                        "message",
                        "category",
                        "stage",
                        "signals",
                        "score",
                        "conversation_risk",
                        "target_id",
                        "author_id",
                    ],
                )
                writer.writeheader()
                for row in reviewed_rows:
                    row = dict(row)
                    row["signals"] = ",".join(row.get("signals", []))
                    writer.writerow(row)
        else:
            raise ValueError("format must be jsonl or csv")

        return output_path, len(reviewed_rows)
