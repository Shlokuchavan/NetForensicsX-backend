"use client";

import {
  CheckCircle2,
  FileSearch,
  Hash,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";

type Evidence = {
  id: string;
  original_filename: string;
  file_size: number;
  sha256: string;
  evidence_type: string;
  status: string;
  created_at: string;
};

function formatBytes(bytes: number) {
  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function EvidenceTable({
  evidence,
}: {
  evidence: Evidence[];
}) {
  if (!evidence.length) {
    return (
      <div className="rounded-xl border border-dashed py-12 text-center">
        <FileSearch className="mx-auto size-8 text-muted-foreground" />

        <p className="mt-3 text-sm font-medium">
          No evidence uploaded
        </p>

        <p className="mt-1 text-xs text-muted-foreground">
          Uploaded PCAP files will appear here.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border">
      <div className="grid grid-cols-[2fr_1fr_1.5fr_2fr] border-b bg-muted/30 px-4 py-3 text-xs font-medium text-muted-foreground">
        <span>Evidence</span>
        <span>Size</span>
        <span>Status</span>
        <span>SHA-256</span>
      </div>

      {evidence.map((item) => (
        <div
          key={item.id}
          className="grid grid-cols-[2fr_1fr_1.5fr_2fr] items-center border-b px-4 py-4 last:border-b-0"
        >
          <div className="flex items-center gap-3">
            <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <FileSearch className="size-4" />
            </div>

            <div>
              <div className="text-sm font-medium">
                {item.original_filename}
              </div>

              <div className="text-xs text-muted-foreground">
                PCAP evidence
              </div>
            </div>
          </div>

          <span className="text-sm text-muted-foreground">
            {formatBytes(item.file_size)}
          </span>

          <Badge className="w-fit border-emerald-500/20 bg-emerald-500/10 text-emerald-400">
            <CheckCircle2 className="mr-1 size-3" />
            {item.status}
          </Badge>

          <div className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
            <Hash className="size-3 shrink-0" />

            <span className="truncate" title={item.sha256}>
              {item.sha256}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}