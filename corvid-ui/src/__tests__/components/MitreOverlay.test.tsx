import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MitreOverlay } from "../../components/MitreOverlay.tsx";

describe("MitreOverlay", () => {
  it("renders technique ID", () => {
    render(<MitreOverlay techniqueId="T1071.001" />);
    expect(screen.getByText("T1071.001")).toBeInTheDocument();
  });

  it("links to MITRE ATT&CK with correct URL", () => {
    render(<MitreOverlay techniqueId="T1071.001" />);
    const link = screen.getByText("T1071.001").closest("a");
    expect(link).toHaveAttribute(
      "href",
      "https://attack.mitre.org/techniques/T1071/001",
    );
    expect(link).toHaveAttribute("target", "_blank");
  });

  it("shows technique name when provided", () => {
    render(
      <MitreOverlay
        techniqueId="T1071.001"
        name="Application Layer Protocol: Web Protocols"
      />,
    );
    expect(
      screen.getByTestId("mitre-name"),
    ).toHaveTextContent("Application Layer Protocol: Web Protocols");
  });

  it("renders tactic tags when provided", () => {
    render(
      <MitreOverlay
        techniqueId="T1071.001"
        tactics={["command-and-control", "exfiltration"]}
      />,
    );
    const tacticsContainer = screen.getByTestId("mitre-tactics");
    expect(tacticsContainer).toBeInTheDocument();
    expect(screen.getByText("command and control")).toBeInTheDocument();
    expect(screen.getByText("exfiltration")).toBeInTheDocument();
  });

  it("renders description when provided", () => {
    render(
      <MitreOverlay
        techniqueId="T1071.001"
        description="Adversaries may communicate using web protocols"
      />,
    );
    expect(
      screen.getByText("Adversaries may communicate using web protocols"),
    ).toBeInTheDocument();
  });

  it("renders without optional props", () => {
    render(<MitreOverlay techniqueId="T1105" />);
    expect(screen.getByTestId("mitre-card")).toBeInTheDocument();
    expect(screen.queryByTestId("mitre-name")).toBeNull();
    expect(screen.queryByTestId("mitre-tactics")).toBeNull();
  });
});
