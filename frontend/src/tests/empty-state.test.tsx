import { render, screen } from "@testing-library/react";

import { EmptyState } from "../pages/empty-state";

describe("EmptyState", () => {
  it("renders title and description", () => {
    render(<EmptyState title="No Case" description="Create one" />);
    expect(screen.getByText("No Case")).toBeDefined();
    expect(screen.getByText("Create one")).toBeDefined();
  });
});
