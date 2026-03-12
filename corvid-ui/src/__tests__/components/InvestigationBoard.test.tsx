/**
 * Tests for the InvestigationBoard keyboard shortcuts.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { InvestigationBoard } from "../../components/InvestigationBoard";
import { useGraphStore } from "../../stores/graphStore";

// Mock dependencies
vi.mock("../../hooks/useAnalysis", () => ({
  useAnalysis: vi.fn(() => ({
    analyze: vi.fn(),
    loading: false,
    error: null,
    response: null,
  })),
}));

vi.mock("../../stores/historyStore", () => ({
  useHistoryStore: vi.fn(() => ({
    saveSession: vi.fn(),
  })),
}));

vi.mock("../../stores/graphStore", () => ({
  useGraphStore: vi.fn(),
}));

vi.mock("../../lib/graphTransforms", () => ({
  analysisToElements: vi.fn(() => ({ nodes: [], edges: [] })),
}));

const mockSelectNode = vi.fn();
const mockRemoveNode = vi.fn();
const mockClearGraph = vi.fn();
const mockSetLayout = vi.fn();
const mockFit = vi.fn();

const mockCyInstance = {
  fit: mockFit,
  nodes: vi.fn(() => ({ style: vi.fn() })),
  edges: vi.fn(() => ({ style: vi.fn() })),
};

describe("InvestigationBoard Keyboard Shortcuts", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    (useGraphStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
      const state = {
        selectedNodeId: null,
        selectNode: mockSelectNode,
        removeNode: mockRemoveNode,
        clearGraph: mockClearGraph,
        setLayout: mockSetLayout,
        cyInstance: mockCyInstance,
        nodes: [],
        edges: [],
      };
      return selector ? selector(state) : state;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("Escape key", () => {
    it("deselects current node when pressed", async () => {
      (useGraphStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
        const state = {
          selectedNodeId: "node-1",
          selectNode: mockSelectNode,
          removeNode: mockRemoveNode,
          clearGraph: mockClearGraph,
          setLayout: mockSetLayout,
          cyInstance: mockCyInstance,
          nodes: [],
          edges: [],
        };
        return selector ? selector(state) : state;
      });

      const user = userEvent.setup();
      render(<InvestigationBoard />);

      await user.keyboard("{Escape}");

      expect(mockSelectNode).toHaveBeenCalledWith(null);
    });
  });

  describe("Delete key", () => {
    it("removes selected node when pressed", async () => {
      (useGraphStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
        const state = {
          selectedNodeId: "node-1",
          selectNode: mockSelectNode,
          removeNode: mockRemoveNode,
          clearGraph: mockClearGraph,
          setLayout: mockSetLayout,
          cyInstance: mockCyInstance,
          nodes: [],
          edges: [],
        };
        return selector ? selector(state) : state;
      });

      const user = userEvent.setup();
      render(<InvestigationBoard />);

      await user.keyboard("{Delete}");

      expect(mockRemoveNode).toHaveBeenCalledWith("node-1");
    });

    it("removes selected node when Backspace pressed", async () => {
      (useGraphStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
        const state = {
          selectedNodeId: "node-1",
          selectNode: mockSelectNode,
          removeNode: mockRemoveNode,
          clearGraph: mockClearGraph,
          setLayout: mockSetLayout,
          cyInstance: mockCyInstance,
          nodes: [],
          edges: [],
        };
        return selector ? selector(state) : state;
      });

      const user = userEvent.setup();
      render(<InvestigationBoard />);

      await user.keyboard("{Backspace}");

      expect(mockRemoveNode).toHaveBeenCalledWith("node-1");
    });

    it("does nothing when no node selected", async () => {
      const user = userEvent.setup();
      render(<InvestigationBoard />);

      await user.keyboard("{Delete}");

      expect(mockRemoveNode).not.toHaveBeenCalled();
    });
  });

  describe("F key", () => {
    it("fits graph to viewport", async () => {
      const user = userEvent.setup();
      render(<InvestigationBoard />);

      await user.keyboard("f");

      expect(mockFit).toHaveBeenCalledWith(undefined, 50);
    });

    it("works with uppercase F", async () => {
      const user = userEvent.setup();
      render(<InvestigationBoard />);

      await user.keyboard("F");

      expect(mockFit).toHaveBeenCalled();
    });

    it("does nothing when no cyInstance", async () => {
      (useGraphStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
        const state = {
          selectedNodeId: null,
          selectNode: mockSelectNode,
          removeNode: mockRemoveNode,
          clearGraph: mockClearGraph,
          setLayout: mockSetLayout,
          cyInstance: null,
          nodes: [],
          edges: [],
        };
        return selector ? selector(state) : state;
      });

      const user = userEvent.setup();
      render(<InvestigationBoard />);

      await user.keyboard("f");

      // Should not throw
      expect(mockFit).not.toHaveBeenCalled();
    });
  });

  describe("Layout keys (1-5)", () => {
    it.each([
      ["1", "dagre"],
      ["2", "cose-bilkent"],
      ["3", "concentric"],
      ["4", "breadthfirst"],
      ["5", "grid"],
    ])("key %s switches to %s layout", async (key, expectedLayout) => {
      const user = userEvent.setup();
      render(<InvestigationBoard />);

      await user.keyboard(key);

      expect(mockSetLayout).toHaveBeenCalledWith(expectedLayout);
    });
  });

  describe("keyboard shortcuts hint", () => {
    it("displays shortcuts at bottom of board", () => {
      render(<InvestigationBoard />);

      expect(screen.getByText("Esc")).toBeInTheDocument();
      expect(screen.getByText("deselect")).toBeInTheDocument();
      expect(screen.getByText("F")).toBeInTheDocument();
      expect(screen.getByText("fit")).toBeInTheDocument();
      expect(screen.getByText("1-5")).toBeInTheDocument();
      expect(screen.getByText("layouts")).toBeInTheDocument();
      expect(screen.getByText("/")).toBeInTheDocument();
      expect(screen.getByText("search")).toBeInTheDocument();
    });
  });

  describe("keyboard shortcuts don't fire in input fields", () => {
    it("does not trigger shortcuts when typing in input", async () => {
      const user = userEvent.setup();
      render(<InvestigationBoard />);

      // Find and focus an input
      const input = screen.getByTestId("ioc-input-bar")?.querySelector("input");
      if (input) {
        await user.click(input);
        await user.type(input, "f");

        expect(mockFit).not.toHaveBeenCalled();
      }
    });
  });
});
