import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { EnrichmentCard } from "../../components/EnrichmentCard.tsx";

describe("EnrichmentCard", () => {
  const sampleData = {
    abuse_confidence_score: 92,
    total_reports: 47,
    country_code: "CN",
    isp: "China Telecom",
  };

  it("renders source name", () => {
    render(<EnrichmentCard source="abuseipdb" data={sampleData} />);
    expect(screen.getByText("abuseipdb")).toBeInTheDocument();
  });

  it("shows field count badge", () => {
    render(<EnrichmentCard source="abuseipdb" data={sampleData} />);
    expect(screen.getByText("4 fields")).toBeInTheDocument();
  });

  it("shows summary of known fields when collapsed", () => {
    render(<EnrichmentCard source="abuseipdb" data={sampleData} />);
    // Should show top known fields in summary row
    expect(screen.getByText(/Abuse Confidence/)).toBeInTheDocument();
  });

  it("expands to show all fields on click", async () => {
    const user = userEvent.setup();
    render(<EnrichmentCard source="abuseipdb" data={sampleData} />);

    // Click to expand
    await user.click(screen.getByText("abuseipdb"));

    const details = screen.getByTestId("enrichment-details");
    expect(details).toBeInTheDocument();
    expect(screen.getByText("92")).toBeInTheDocument();
    expect(screen.getByText("47")).toBeInTheDocument();
  });

  it("handles unknown source gracefully", () => {
    render(
      <EnrichmentCard
        source="custom_source"
        data={{ key1: "value1", key2: 42 }}
      />,
    );
    expect(screen.getByText("custom_source")).toBeInTheDocument();
    expect(screen.getByText("2 fields")).toBeInTheDocument();
  });

  it("renders nothing for null data", () => {
    const { container } = render(
      <EnrichmentCard source="abuseipdb" data={null} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("handles boolean values in expansion", async () => {
    const user = userEvent.setup();
    render(
      <EnrichmentCard
        source="abuseipdb"
        data={{ is_tor: true, is_whitelisted: false }}
      />,
    );

    await user.click(screen.getByText("abuseipdb"));
    expect(screen.getByText("Yes")).toBeInTheDocument();
    expect(screen.getByText("No")).toBeInTheDocument();
  });

  it("handles array values in expansion", async () => {
    const user = userEvent.setup();
    render(
      <EnrichmentCard
        source="urlhaus"
        data={{ tags: ["malware", "botnet"] }}
      />,
    );

    await user.click(screen.getByText("urlhaus"));
    expect(screen.getByText("malware, botnet")).toBeInTheDocument();
  });
});
