/**
 * Tests for the LayoutSwitcher component.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { LayoutSwitcher } from "../../components/LayoutSwitcher";
import { useGraphStore } from "../../stores/graphStore";

// Mock Zustand store
vi.mock("../../stores/graphStore", () => ({
  useGraphStore: vi.fn(),
}));

const mockSetLayout = vi.fn();

describe("LayoutSwitcher", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (useGraphStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
      const state = {
        activeLayout: "dagre",
        setLayout: mockSetLayout,
      };
      return selector ? selector(state) : state;
    });
  });

  it("renders layout switcher button", () => {
    render(<LayoutSwitcher />);
    expect(screen.getByTestId("layout-switcher")).toBeInTheDocument();
  });

  it("displays current layout name on button", () => {
    render(<LayoutSwitcher />);
    expect(screen.getByText("Dagre")).toBeInTheDocument();
  });

  it("opens dropdown when clicked", async () => {
    const user = userEvent.setup();
    render(<LayoutSwitcher />);

    const button = screen.getByTestId("layout-switcher");
    await user.click(button);

    expect(screen.getByText("Layout Algorithm")).toBeInTheDocument();
    expect(screen.getByText("Dagre")).toBeInTheDocument();
    expect(screen.getByText("COSE")).toBeInTheDocument();
    expect(screen.getByText("Concentric")).toBeInTheDocument();
    expect(screen.getByText("Breadth-first")).toBeInTheDocument();
    expect(screen.getByText("Grid")).toBeInTheDocument();
  });

  it("shows descriptions for each layout", async () => {
    const user = userEvent.setup();
    render(<LayoutSwitcher />);

    const button = screen.getByTestId("layout-switcher");
    await user.click(button);

    expect(screen.getByText("Hierarchical top-down")).toBeInTheDocument();
    expect(screen.getByText("Organic clustering")).toBeInTheDocument();
    expect(screen.getByText("Severity-focused rings")).toBeInTheDocument();
    expect(screen.getByText("Tree layout for chains")).toBeInTheDocument();
    expect(screen.getByText("Side-by-side comparison")).toBeInTheDocument();
  });

  it("displays keyboard shortcuts for layouts", async () => {
    const user = userEvent.setup();
    render(<LayoutSwitcher />);

    const button = screen.getByTestId("layout-switcher");
    await user.click(button);

    expect(screen.getByText("1")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
  });

  it("shows checkmark on active layout", async () => {
    const user = userEvent.setup();
    render(<LayoutSwitcher />);

    const button = screen.getByTestId("layout-switcher");
    await user.click(button);

    const activeOption = screen.getByRole("option", { selected: true });
    expect(activeOption).toHaveTextContent("Dagre");
  });

  it("highlights active layout with accent color", async () => {
    const user = userEvent.setup();
    render(<LayoutSwitcher />);

    const button = screen.getByTestId("layout-switcher");
    await user.click(button);

    const dagreOption = screen.getByRole("option", { selected: true });
    expect(dagreOption).toHaveClass("bg-accent/10");
  });

  it("calls setLayout when a different layout is selected", async () => {
    const user = userEvent.setup();
    render(<LayoutSwitcher />);

    const button = screen.getByTestId("layout-switcher");
    await user.click(button);

    const coseOption = screen.getByText("COSE").closest("button");
    await user.click(coseOption!);

    expect(mockSetLayout).toHaveBeenCalledWith("cose-bilkent");
  });

  it("closes dropdown after selecting", async () => {
    const user = userEvent.setup();
    render(<LayoutSwitcher />);

    const button = screen.getByTestId("layout-switcher");
    await user.click(button);

    expect(screen.getByText("Layout Algorithm")).toBeInTheDocument();

    const coseOption = screen.getByText("COSE").closest("button");
    await user.click(coseOption!);

    expect(screen.queryByText("Layout Algorithm")).not.toBeInTheDocument();
  });

  it("closes dropdown when clicking outside", async () => {
    const user = userEvent.setup();
    render(
      <>
        <LayoutSwitcher />
        <div data-testid="outside">Outside</div>
      </>
    );

    const button = screen.getByTestId("layout-switcher");
    await user.click(button);

    expect(screen.getByText("Layout Algorithm")).toBeInTheDocument();

    const outside = screen.getByTestId("outside");
    await user.click(outside);

    expect(screen.queryByText("Layout Algorithm")).not.toBeInTheDocument();
  });

  it("displays correct label for COSE layout when active", async () => {
    (useGraphStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
      const state = {
        activeLayout: "cose-bilkent",
        setLayout: mockSetLayout,
      };
      return selector ? selector(state) : state;
    });

    render(<LayoutSwitcher />);
    expect(screen.getByText("COSE")).toBeInTheDocument();
  });

  it("displays correct label for concentric layout when active", async () => {
    (useGraphStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
      const state = {
        activeLayout: "concentric",
        setLayout: mockSetLayout,
      };
      return selector ? selector(state) : state;
    });

    render(<LayoutSwitcher />);
    expect(screen.getByText("Concentric")).toBeInTheDocument();
  });
});
