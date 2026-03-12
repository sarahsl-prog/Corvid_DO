/**
 * Tests for the HistoryDrawer component.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HistoryDrawer } from "../../components/HistoryDrawer";
import { useHistoryStore } from "../../stores/historyStore";
import { useGraphStore } from "../../stores/graphStore";
import type { InvestigationSession } from "../../stores/historyStore";

// Mock Zustand stores
vi.mock("../../stores/historyStore", () => ({
  useHistoryStore: vi.fn(),
}));

vi.mock("../../stores/graphStore", () => ({
  useGraphStore: vi.fn(),
}));

const mockDeleteSession = vi.fn();
const mockClearHistory = vi.fn();
const mockClearGraph = vi.fn();
const mockAddElements = vi.fn();
const mockOnClose = vi.fn();

const mockSessions: InvestigationSession[] = [
  {
    id: "session-1",
    name: "Test Investigation 1",
    timestamp: Date.now() - 1000 * 60 * 5, // 5 minutes ago
    nodes: [{ data: { id: "node-1", label: "192.168.1.1", nodeType: "ioc" } }],
    edges: [],
    results: [
      {
        ioc: { type: "ip", value: "192.168.1.1" },
        severity: 7.5,
        confidence: 0.85,
        summary: "Malicious IP",
        related_cves: [],
        mitre_techniques: [],
        enrichments: {},
        recommended_actions: [],
      },
    ],
  },
  {
    id: "session-2",
    name: "Test Investigation 2",
    timestamp: Date.now() - 1000 * 60 * 60, // 1 hour ago
    nodes: [
      { data: { id: "node-1", label: "192.168.1.1", nodeType: "ioc" } },
      { data: { id: "node-2", label: "CVE-2024-1234", nodeType: "cve" } },
    ],
    edges: [{ data: { source: "node-1", target: "node-2", edgeType: "has_cve" } }],
    results: [
      {
        ioc: { type: "ip", value: "192.168.1.1" },
        severity: 9.0,
        confidence: 0.95,
        summary: "Critical",
        related_cves: ["CVE-2024-1234"],
        mitre_techniques: [],
        enrichments: {},
        recommended_actions: [],
      },
      {
        ioc: { type: "domain", value: "evil.com" },
        severity: 8.0,
        confidence: 0.9,
        summary: "Malicious domain",
        related_cves: [],
        mitre_techniques: [],
        enrichments: {},
        recommended_actions: [],
      },
    ],
  },
];

describe("HistoryDrawer", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.setSystemTime(new Date("2026-03-02T12:00:00Z"));

    (useHistoryStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
      const state = {
        sessions: mockSessions,
        loadSession: vi.fn((id: string) => mockSessions.find((s) => s.id === id) || null),
        deleteSession: mockDeleteSession,
        clearHistory: mockClearHistory,
      };
      return selector ? selector(state) : state;
    });

    (useGraphStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
      const state = {
        clearGraph: mockClearGraph,
        addElements: mockAddElements,
      };
      return selector ? selector(state) : state;
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("when open", () => {
    it("renders drawer with investigation history", () => {
      render(<HistoryDrawer isOpen={true} onClose={mockOnClose} />);

      expect(screen.getByText("Investigation History")).toBeInTheDocument();
      expect(screen.getByText("Test Investigation 1")).toBeInTheDocument();
      expect(screen.getByText("Test Investigation 2")).toBeInTheDocument();
    });

    it("shows node count for each session", () => {
      render(<HistoryDrawer isOpen={true} onClose={mockOnClose} />);

      expect(screen.getByText("1 nodes")).toBeInTheDocument();
      expect(screen.getByText("2 nodes")).toBeInTheDocument();
    });

    it("shows relative timestamps", () => {
      render(<HistoryDrawer isOpen={true} onClose={mockOnClose} />);

      expect(screen.getByText("5m ago")).toBeInTheDocument();
      expect(screen.getByText("1h ago")).toBeInTheDocument();
    });

    it("marks most recent session with Latest badge", () => {
      render(<HistoryDrawer isOpen={true} onClose={mockOnClose} />);

      const badges = screen.getAllByText("Latest");
      expect(badges).toHaveLength(1);
      expect(screen.getByText("Test Investigation 1").parentElement).toContainElement(badges[0]);
    });

    it("shows IOC preview badges", () => {
      render(<HistoryDrawer isOpen={true} onClose={mockOnClose} />);

      // Session 2 has 2 IOCs, should show "+1 more" since we show truncated
      expect(screen.getByText("192.168...")).toBeInTheDocument();
      expect(screen.getByText("+1 more")).toBeInTheDocument();
    });

    it("closes drawer when backdrop clicked", async () => {
      const user = userEvent.setup();
      render(<HistoryDrawer isOpen={true} onClose={mockOnClose} />);

      const backdrop = document.querySelector(".bg-black/50");
      await user.click(backdrop!);

      expect(mockOnClose).toHaveBeenCalled();
    });

    it("closes drawer when X button clicked", async () => {
      const user = userEvent.setup();
      render(<HistoryDrawer isOpen={true} onClose={mockOnClose} />);

      const closeButton = screen.getByLabelText(/close/i);
      await user.click(closeButton);

      expect(mockOnClose).toHaveBeenCalled();
    });

    it("loads session when clicked", async () => {
      const user = userEvent.setup();
      render(<HistoryDrawer isOpen={true} onClose={mockOnClose} />);

      const session2 = screen.getByText("Test Investigation 2").closest("div[class*=group]");
      await user.click(session2!);

      await waitFor(() => {
        expect(mockClearGraph).toHaveBeenCalled();
        expect(mockAddElements).toHaveBeenCalledWith(
          mockSessions[1].nodes,
          mockSessions[1].edges
        );
        expect(mockOnClose).toHaveBeenCalled();
      });
    });

    it("deletes session when delete button clicked", async () => {
      const user = userEvent.setup();
      render(<HistoryDrawer isOpen={true} onClose={mockOnClose} />);

      const deleteButtons = screen.getAllByTitle("Delete this session");
      await user.click(deleteButtons[0]);

      expect(mockDeleteSession).toHaveBeenCalledWith("session-1");
    });

    it("shows clear all button when sessions exist", () => {
      render(<HistoryDrawer isOpen={true} onClose={mockOnClose} />);

      expect(screen.getByTitle("Clear all history")).toBeInTheDocument();
    });

    it("shows confirmation modal when clear all clicked", async () => {
      const user = userEvent.setup();
      render(<HistoryDrawer isOpen={true} onClose={mockOnClose} />);

      const clearButton = screen.getByTitle("Clear all history");
      await user.click(clearButton);

      expect(screen.getByText(/Clear all \d+ investigations/i)).toBeInTheDocument();
      expect(screen.getByText("Clear All")).toBeInTheDocument();
      expect(screen.getByText("Cancel")).toBeInTheDocument();
    });

    it("clears all sessions when confirmed", async () => {
      const user = userEvent.setup();
      render(<HistoryDrawer isOpen={true} onClose={mockOnClose} />);

      const clearButton = screen.getByTitle("Clear all history");
      await user.click(clearButton);

      const confirmButton = screen.getByText("Clear All");
      await user.click(confirmButton);

      expect(mockClearHistory).toHaveBeenCalled();
    });
  });

  describe("when closed", () => {
    it("does not render content", () => {
      render(<HistoryDrawer isOpen={false} onClose={mockOnClose} />);

      expect(screen.queryByText("Investigation History")).not.toBeInTheDocument();
    });
  });

  describe("empty state", () => {
    beforeEach(() => {
      (useHistoryStore as unknown as ReturnType<typeof vi.fn>).mockImplementation((selector) => {
        const state = {
          sessions: [],
          loadSession: vi.fn(),
          deleteSession: mockDeleteSession,
          clearHistory: mockClearHistory,
        };
        return selector ? selector(state) : state;
      });
    });

    it("shows empty state message", () => {
      render(<HistoryDrawer isOpen={true} onClose={mockOnClose} />);

      expect(screen.getByText("No investigations yet")).toBeInTheDocument();
      expect(screen.getByText(/Submit an IOC for analysis/)).toBeInTheDocument();
    });

    it("does not show clear button when empty", () => {
      render(<HistoryDrawer isOpen={true} onClose={mockOnClose} />);

      expect(screen.queryByTitle("Clear all history")).not.toBeInTheDocument();
    });
  });
});
