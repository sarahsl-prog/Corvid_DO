import { InvestigationBoard } from "./components/InvestigationBoard.tsx";
import "./index.css";

function App() {
  return (
    <div className="h-screen w-screen overflow-hidden bg-bg-primary">
      {/* Header */}
      <header className="flex h-12 items-center border-b border-bg-tertiary bg-bg-secondary px-4">
        <h1 className="text-lg font-bold text-text-primary">
          <span className="text-accent">Corvid</span>{" "}
          <span className="text-text-secondary font-normal">Investigation Board</span>
        </h1>
      </header>

      {/* Main workspace */}
      <main className="h-[calc(100vh-3rem)]">
        <InvestigationBoard />
      </main>
    </div>
  );
}

export default App;
