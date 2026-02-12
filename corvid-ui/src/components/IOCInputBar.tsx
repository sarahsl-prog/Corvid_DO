/**
 * IOC submission form with auto-type detection and validation.
 *
 * Supports single IOC entry and multi-line paste (one IOC per line).
 */

import { useState, useCallback, type FormEvent, type ChangeEvent } from "react";
import { Search, Send } from "lucide-react";
import { detectIOCType, ALL_IOC_TYPES, IOC_TYPE_LABELS } from "../lib/constants.ts";
import type { IOCType, IOCCreate, AnalyzeRequest } from "../types/api.ts";

interface IOCInputBarProps {
  onSubmit: (request: AnalyzeRequest) => void;
  disabled?: boolean;
}

export function IOCInputBar({ onSubmit, disabled = false }: IOCInputBarProps) {
  const [value, setValue] = useState("");
  const [iocType, setIOCType] = useState<IOCType | "">("");
  const [context, setContext] = useState("");
  const [priority, setPriority] = useState<"low" | "medium" | "high">("medium");
  const [showContext, setShowContext] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  // Auto-detect IOC type on value change
  const handleValueChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    const newValue = e.target.value;
    setValue(newValue);
    setValidationError(null);

    const detected = detectIOCType(newValue);
    if (detected) {
      setIOCType(detected);
    }
  }, []);

  const handleSubmit = useCallback(
    (e: FormEvent) => {
      e.preventDefault();

      const trimmed = value.trim();
      if (!trimmed) {
        setValidationError("Enter at least one IOC");
        return;
      }

      // Support multi-line paste: split by newlines
      const lines = trimmed
        .split(/\n/)
        .map((l) => l.trim())
        .filter(Boolean);

      const iocs: IOCCreate[] = [];
      for (const line of lines) {
        const detectedType = detectIOCType(line);
        // Use the manually selected type for single IOC, or auto-detect for batch
        const type = lines.length === 1 && iocType ? iocType : detectedType;
        if (!type) {
          setValidationError(`Could not detect type for: "${line}"`);
          return;
        }
        iocs.push({ type, value: line });
      }

      if (iocs.length > 10) {
        setValidationError("Maximum 10 IOCs per request");
        return;
      }

      onSubmit({
        iocs,
        context: context.trim() || undefined,
        priority,
      });

      // Clear form
      setValue("");
      setIOCType("");
      setContext("");
      setValidationError(null);
    },
    [value, iocType, context, priority, onSubmit],
  );

  return (
    <form
      onSubmit={handleSubmit}
      className="flex flex-col gap-2 rounded-lg bg-bg-secondary p-3"
      data-testid="ioc-input-bar"
    >
      <div className="flex items-center gap-2">
        {/* IOC value input */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            value={value}
            onChange={handleValueChange}
            placeholder="Enter IOC (IP, domain, hash, URL, email)..."
            disabled={disabled}
            className="w-full rounded-md border border-bg-tertiary bg-bg-primary py-2 pl-10 pr-3 text-sm text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none disabled:opacity-50"
            data-testid="ioc-value-input"
          />
        </div>

        {/* Type selector */}
        <select
          value={iocType}
          onChange={(e) => setIOCType(e.target.value as IOCType | "")}
          disabled={disabled}
          className="rounded-md border border-bg-tertiary bg-bg-primary px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none disabled:opacity-50"
          data-testid="ioc-type-select"
        >
          <option value="">Auto-detect</option>
          {ALL_IOC_TYPES.map((t) => (
            <option key={t} value={t}>
              {IOC_TYPE_LABELS[t]}
            </option>
          ))}
        </select>

        {/* Priority */}
        <select
          value={priority}
          onChange={(e) => setPriority(e.target.value as "low" | "medium" | "high")}
          disabled={disabled}
          className="rounded-md border border-bg-tertiary bg-bg-primary px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none disabled:opacity-50"
          data-testid="priority-select"
        >
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
        </select>

        {/* Context toggle */}
        <button
          type="button"
          onClick={() => setShowContext(!showContext)}
          disabled={disabled}
          className="rounded-md border border-bg-tertiary bg-bg-primary px-3 py-2 text-sm text-text-secondary hover:text-text-primary focus:border-accent focus:outline-none disabled:opacity-50"
        >
          + Context
        </button>

        {/* Submit */}
        <button
          type="submit"
          disabled={disabled || !value.trim()}
          className="flex items-center gap-2 rounded-md bg-accent px-4 py-2 text-sm font-medium text-bg-primary hover:bg-accent-hover focus:outline-none disabled:opacity-50"
          data-testid="analyze-button"
        >
          <Send className="h-4 w-4" />
          Analyze
        </button>
      </div>

      {/* Context textarea (togglable) */}
      {showContext && (
        <textarea
          value={context}
          onChange={(e) => setContext(e.target.value)}
          placeholder="Optional: describe where/how the IOC was observed..."
          maxLength={2000}
          disabled={disabled}
          className="rounded-md border border-bg-tertiary bg-bg-primary p-2 text-sm text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none disabled:opacity-50"
          rows={2}
          data-testid="context-input"
        />
      )}

      {/* Validation error */}
      {validationError && (
        <p className="text-sm text-severity-9" data-testid="validation-error">
          {validationError}
        </p>
      )}
    </form>
  );
}
