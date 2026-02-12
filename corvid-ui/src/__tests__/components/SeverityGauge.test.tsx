import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { SeverityGauge } from "../../components/SeverityGauge.tsx";

describe("SeverityGauge", () => {
  it("renders severity score", () => {
    render(<SeverityGauge severity={7.8} />);
    expect(screen.getByTestId("severity-score")).toHaveTextContent("7.8");
  });

  it("renders green color for low severity", () => {
    render(<SeverityGauge severity={0} />);
    const score = screen.getByTestId("severity-score");
    expect(score.style.color).toBe("rgb(34, 197, 94)"); // #22c55e
  });

  it("renders red color for high severity", () => {
    render(<SeverityGauge severity={10} />);
    const score = screen.getByTestId("severity-score");
    expect(score.style.color).toBe("rgb(220, 38, 38)"); // #dc2626
  });

  it("renders N/A for null severity", () => {
    render(<SeverityGauge severity={null} />);
    expect(screen.getByText("Severity: N/A")).toBeInTheDocument();
  });

  it("renders N/A for undefined severity", () => {
    render(<SeverityGauge severity={undefined} />);
    expect(screen.getByText("Severity: N/A")).toBeInTheDocument();
  });
});
