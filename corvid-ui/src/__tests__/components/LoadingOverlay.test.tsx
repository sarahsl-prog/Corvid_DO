import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { LoadingOverlay } from "../../components/LoadingOverlay.tsx";

describe("LoadingOverlay", () => {
  it("renders when loading is true", () => {
    render(<LoadingOverlay loading={true} />);
    expect(screen.getByTestId("loading-overlay")).toBeInTheDocument();
    expect(screen.getByText("Analyzing IOCs...")).toBeInTheDocument();
  });

  it("renders nothing when loading is false", () => {
    const { container } = render(<LoadingOverlay loading={false} />);
    expect(container.firstChild).toBeNull();
  });

  it("shows custom message when provided", () => {
    render(<LoadingOverlay loading={true} message="Enriching data..." />);
    expect(screen.getByText("Enriching data...")).toBeInTheDocument();
  });
});
