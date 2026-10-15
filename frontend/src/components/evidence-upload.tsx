"use client";

import { useRef, useState } from "react";
import {
  CheckCircle2,
  FileUp,
  Loader2,
  UploadCloud,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { uploadEvidence } from "@/lib/api";

type Props = {
  caseId: string;
  onUploaded?: () => void;
};

export function EvidenceUpload({
  caseId,
  onUploaded,
}: Props) {
  const inputRef = useRef<HTMLInputElement>(null);

  const [uploading, setUploading] = useState(false);
  const [uploaded, setUploaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleFile(file: File) {
    setError(null);
    setUploaded(false);
    setUploading(true);

    try {
      await uploadEvidence(caseId, file);

      setUploaded(true);
      onUploaded?.();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Upload failed"
      );
    } finally {
      setUploading(false);
    }
  }

  function handleChange(
    event: React.ChangeEvent<HTMLInputElement>
  ) {
    const file = event.target.files?.[0];

    if (file) {
      void handleFile(file);
    }
  }

  return (
    <div className="rounded-xl border border-dashed bg-card/50 p-8 text-center">
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng,.cap"
        className="hidden"
        onChange={handleChange}
      />

      <div className="mx-auto flex size-14 items-center justify-center rounded-2xl bg-primary/10 text-primary">
        {uploading ? (
          <Loader2 className="size-7 animate-spin" />
        ) : uploaded ? (
          <CheckCircle2 className="size-7" />
        ) : (
          <UploadCloud className="size-7" />
        )}
      </div>

      <h3 className="mt-4 font-semibold">
        {uploading
          ? "Uploading evidence..."
          : uploaded
            ? "Evidence uploaded"
            : "Upload network evidence"}
      </h3>

      <p className="mx-auto mt-2 max-w-md text-sm text-muted-foreground">
        Add a PCAP, PCAPNG, or CAP capture. NetForensicX will
        preserve the original file and calculate its SHA-256
        integrity hash.
      </p>

      <Button
        className="mt-5"
        variant="outline"
        disabled={uploading}
        onClick={() => inputRef.current?.click()}
      >
        <FileUp className="size-4" />
        Choose PCAP
      </Button>

      {error && (
        <p className="mt-4 text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}