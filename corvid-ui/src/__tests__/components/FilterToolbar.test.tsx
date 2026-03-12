/**
 * Tests for the FilterToolbar component.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FilterToolbar } from "../../components/FilterToolbar";
import { useFilterStore } from "../../stores/filterStore";
import { useGraphStore } from "../../stores/graphStore";

// Mock Zustand stores
vi.mock("../../stores/filterStore", () => ({
  useFilterStore: vi.fn(),
}));

vi.mock("../../stores/graphStore", () => ({
  useGraphStore: vi.fn(),
}));

const mockToggleIOCType = vi.fn();
const mockToggleNodeType = vi.fn();
const mockToggleSource = vi.fn();
const mockSetSeverityRange = vi.fn();
const mockSetConfidenceThreshold = vi.fn();
const mockResetFilters = vi.fn();

const mockCyInstance = {
  nodes: vi.fn(() => ({
    forEach: vi.fn((cb) => {
      cb({
        data: () => ({ nodeType: "ioc", iocType: "ip", severity: 7.5, confidence: 0.85 }),
        style: vi.fn(),
      });
    }),
    style: vi.fn(),
    slice: vi.fn(),
    length: 2,
  })),
  edges: vi.fn(() => ({
    forEach: vi.fn(),
    style: vi.fn(),
  })),
};

describe("FilterToolbar", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Default filter store state
    (useFilterStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
      const state = {
        severityRange: [0, 10] as [number, number],
        confidenceThreshold: 0,
        iocTypes: new Set<string>(),
        nodeTypes: new Set<string>(),
        sources: new Set<string>(),
        setSeverityRange: mockSetSeverityRange,
        setConfidenceThreshold: mockSetConfidenceThreshold,
        toggleIOCType: mockToggleIOCType,
        toggleNodeType: mockToggleNodeType,
        toggleSource: mockToggleSource,
        resetFilters: mockResetFilters,
      };
      return selector ? selector(state) : state;
    });

    // Default graph store state
    (useGraphStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
      const state = {
        cyInstance: mockCyInstance,
      };
      return selector ? selector(state) : state;
    });
  });

  it("renders filter toolbar with all sections", () => {
    render(<FilterToolbar />);

    expect(screen.getByText("Filters")).toBeInTheDocument();
    expect(screen.getByText("Severity Range")).toBeInTheDocument();
    expect(screen.getByText("Min Confidence")).toBeInTheDocument();
    expect(screen.getByText("Node Types")).toBeInTheDocument();
    expect(screen.getByText("IOC Types")).toBeInTheDocument();
    expect(screen.getByText("Highlight Sources")).toBeInTheDocument();
  });

  it("displays current severity range values", () => {
    (useFilterStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
      const state = {
        severityRange: [3, 7] as [number, number],
        confidenceThreshold: 0,
        iocTypes: new Set<string>(),
        nodeTypes: new Set<string>(),
        sources: new Set<string>(),
        setSeverityRange: mockSetSeverityRange,
        setConfidenceThreshold: mockSetConfidenceThreshold,
        toggleIOCType: mockToggleIOCType,
        toggleNodeType: mockToggleNodeType,
        toggleSource: mockToggleSource,
        resetFilters: mockResetFilters,
      };
      return selector ? selector(state) : state;
    });

    render(<FilterToolbar />);

    expect(screen.getByText("3.0")).toBeInTheDocument();
    expect(screen.getByText("7.0")).toBeInTheDocument();
  });

  it("calls setSeverityRange when severity slider changes", async () => {
    const user = userEvent.setup();
    render(<FilterToolbar />);

    const minSlider = screen.getAllByRole("slider")[0];
    await user.clear(minSlider);
    await user.type(minSlider, "2.5");

    expect(mockSetSeverityRange).toHaveBeenCalledWith([2.5, 10]);
  });

  it("displays current confidence threshold", () => {
    (useFilterStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
      const state = {
        severityRange: [0, 10] as [number, number],
        confidenceThreshold: 0.75,
        iocTypes: new Set<string>(),
        nodeTypes: new Set<string>(),
        sources: new Set<string>(),
        setSeverityRange: mockSetSeverityRange,
        setConfidenceThreshold: mockSetConfidenceThreshold,
        toggleIOCType: mockToggleIOCType,
        toggleNodeType: mockToggleNodeType,
        toggleSource: mockToggleSource,
        resetFilters: mockResetFilters,
      };
      return selector ? selector(state) : state;
    });

    render(<FilterToolbar />);

    expect(screen.getByText("75")).toBeInTheDocument();
  });

  it("calls setConfidenceThreshold when confidence slider changes", async () => {
    const user = userEvent.setup();
    render(<FilterToolbar />);

    const confidenceSlider = screen.getAllByRole("slider")[2];
    await user.clear(confidenceSlider);
    await user.type(confidenceSlider, "0.5");

    expect(mockSetConfidenceThreshold).toHaveBeenCalledWith(0.5);
  });

  it("toggles IOC type when checkbox clicked", async () => {
    const user = userEvent.setup();
    render(<FilterToolbar />);

    const ipCheckbox = screen.getByLabelText("IP Address");
    await user.click(ipCheckbox);

    expect(mockToggleIOCType).toHaveBeenCalledWith("ip");
  });

  it("toggles node type when checkbox clicked", async () => {
    const user = userEvent.setup();
    render(<FilterToolbar />);

    const iocCheckbox = screen.getByLabelText("IOC");
    await user.click(iocCheckbox);

    expect(mockToggleNodeType).toHaveBeenCalledWith("ioc");
  });

  it("toggles source when checkbox clicked", async () => {
    const user = userEvent.setup();
    render(<FilterToolbar />);

    const abuseCheckbox = screen.getByLabelText("abuseipdb");
    await user.click(abuseCheckbox);

    expect(mockToggleSource).toHaveBeenCalledWith("abuseipdb");
  });

  it("shows checked state for selected IOC types", () => {
    (useFilterStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
      const state = {
        severityRange: [0, 10] as [number, number],
        confidenceThreshold: 0,
        iocTypes: new Set(["ip", "domain"]),
        nodeTypes: new Set<string>(),
        sources: new Set<string>(),
        setSeverityRange: mockSetSeverityRange,
        setConfidenceThreshold: mockSetConfidenceThreshold,
        toggleIOCType: mockToggleIOCType,
        toggleNodeType: mockToggleNodeType,
        toggleSource: mockToggleSource,
        resetFilters: mockResetFilters,
      };
      return selector ? selector(state) : state;
    });

    render(<FilterToolbar />);

    const ipCheckbox = screen.getByLabelText("IP Address") as HTMLInputElement;
    expect(ipCheckbox.checked).toBe(true);

    const domainCheckbox = screen.getByLabelText("Domain") as HTMLInputElement;
    expect(domainCheckbox.checked).toBe(true);
  });

  it("shows reset button when filters are active", () => {
    (useFilterStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
      const state = {
        severityRange: [2, 10] as [number, number],
        confidenceThreshold: 0.5,
        iocTypes: new Set(["ip"]),
        nodeTypes: new Set<string>(),
        sources: new Set<string>(),
        setSeverityRange: mockSetSeverityRange,
        setConfidenceThreshold: mockSetConfidenceThreshold,
        toggleIOCType: mockToggleIOCType,
        toggleNodeType: mockToggleNodeType,
        toggleSource: mockToggleSource,
        resetFilters: mockResetFilters,
      };
      return selector ? selector(state) : state;
    });

    render(<FilterToolbar />);

    expect(screen.getByText("Reset")).toBeInTheDocument();
  });

  it("calls resetFilters when reset button clicked", async () => {
    (useFilterStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
      const state = {
        severityRange: [2, 8] as [number, number],
        confidenceThreshold: 0.5,
        iocTypes: new Set(["ip"]),
        nodeTypes: new Set<string>(),
        sources: new Set<string>(),
        setSeverityRange: mockSetSeverityRange,
        setConfidenceThreshold: mockSetConfidenceThreshold,
        toggleIOCType: mockToggleIOCType,
        toggleNodeType: mockToggleNodeType,
        toggleSource: mockToggleSource,
        resetFilters: mockResetFilters,
      };
      return selector ? selector(state) : state;
    });

    const user = userEvent.setup();
    render(<FilterToolbar />);

    const resetButton = screen.getByText("Reset");
    await user.click(resetButton);

    expect(mockResetFilters).toHaveBeenCalled();
  });

  it("hides reset button when no filters active", () => {
    render(<FilterToolbar />);

    expect(screen.queryByText("Reset")).not.toBeInTheDocument();
  });
});
