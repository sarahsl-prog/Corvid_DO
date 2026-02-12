import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IOCInputBar } from "../../components/IOCInputBar.tsx";

describe("IOCInputBar", () => {
  it("renders the input form", () => {
    render(<IOCInputBar onSubmit={vi.fn()} />);
    expect(screen.getByTestId("ioc-value-input")).toBeInTheDocument();
    expect(screen.getByTestId("ioc-type-select")).toBeInTheDocument();
    expect(screen.getByTestId("analyze-button")).toBeInTheDocument();
  });

  it("auto-detects IP type on input", async () => {
    const user = userEvent.setup();
    render(<IOCInputBar onSubmit={vi.fn()} />);

    await user.type(screen.getByTestId("ioc-value-input"), "203.0.113.42");
    expect(screen.getByTestId("ioc-type-select")).toHaveValue("ip");
  });

  it("auto-detects SHA-256 hash type", async () => {
    const user = userEvent.setup();
    render(<IOCInputBar onSubmit={vi.fn()} />);

    const hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    await user.type(screen.getByTestId("ioc-value-input"), hash);
    expect(screen.getByTestId("ioc-type-select")).toHaveValue("hash_sha256");
  });

  it("calls onSubmit with correct payload", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();
    render(<IOCInputBar onSubmit={onSubmit} />);

    await user.type(screen.getByTestId("ioc-value-input"), "203.0.113.42");
    await user.click(screen.getByTestId("analyze-button"));

    expect(onSubmit).toHaveBeenCalledWith({
      iocs: [{ type: "ip", value: "203.0.113.42" }],
      context: undefined,
      priority: "medium",
    });
  });

  it("shows validation error for empty input", async () => {
    const user = userEvent.setup();
    render(<IOCInputBar onSubmit={vi.fn()} />);

    // The button should be disabled with empty input
    const button = screen.getByTestId("analyze-button");
    expect(button).toBeDisabled();

    // Type and then clear
    await user.type(screen.getByTestId("ioc-value-input"), "a");
    await user.clear(screen.getByTestId("ioc-value-input"));
    // Can't click disabled button, so just verify it's disabled
    expect(button).toBeDisabled();
  });

  it("shows validation error for unrecognized IOC format", async () => {
    const user = userEvent.setup();
    render(<IOCInputBar onSubmit={vi.fn()} />);

    await user.type(screen.getByTestId("ioc-value-input"), "not-an-ioc");
    await user.click(screen.getByTestId("analyze-button"));

    expect(screen.getByTestId("validation-error")).toBeInTheDocument();
  });

  it("clears form after successful submit", async () => {
    const user = userEvent.setup();
    render(<IOCInputBar onSubmit={vi.fn()} />);

    const input = screen.getByTestId("ioc-value-input");
    await user.type(input, "203.0.113.42");
    await user.click(screen.getByTestId("analyze-button"));

    expect(input).toHaveValue("");
  });

  it("disables form when disabled prop is true", () => {
    render(<IOCInputBar onSubmit={vi.fn()} disabled />);
    expect(screen.getByTestId("ioc-value-input")).toBeDisabled();
    expect(screen.getByTestId("analyze-button")).toBeDisabled();
  });

  it("shows context textarea when context button clicked", async () => {
    const user = userEvent.setup();
    render(<IOCInputBar onSubmit={vi.fn()} />);

    await user.click(screen.getByText("+ Context"));
    expect(screen.getByTestId("context-input")).toBeInTheDocument();
  });
});
