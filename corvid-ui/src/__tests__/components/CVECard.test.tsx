import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { CVECard } from "../../components/CVECard.tsx";

describe("CVECard", () => {
  it("renders CVE ID", () => {
    render(<CVECard cveId="CVE-2024-21762" />);
    expect(screen.getByText("CVE-2024-21762")).toBeInTheDocument();
  });

  it("links to NVD", () => {
    render(<CVECard cveId="CVE-2024-21762" />);
    const link = screen.getByText("CVE-2024-21762").closest("a");
    expect(link).toHaveAttribute(
      "href",
      "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
    );
    expect(link).toHaveAttribute("target", "_blank");
  });

  it("shows CVSS badge when score provided", () => {
    render(<CVECard cveId="CVE-2024-21762" cvssScore={9.8} />);
    const badge = screen.getByTestId("cvss-badge");
    expect(badge).toHaveTextContent("9.8");
  });

  it("hides CVSS badge when score not provided", () => {
    render(<CVECard cveId="CVE-2024-21762" />);
    expect(screen.queryByTestId("cvss-badge")).toBeNull();
  });

  it("shows description when provided", () => {
    render(
      <CVECard
        cveId="CVE-2024-21762"
        description="A critical vulnerability in FortiOS"
      />,
    );
    expect(
      screen.getByText("A critical vulnerability in FortiOS"),
    ).toBeInTheDocument();
  });

  it("has correct test id", () => {
    render(<CVECard cveId="CVE-2024-21762" />);
    expect(screen.getByTestId("cve-card")).toBeInTheDocument();
  });
});
