import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CommandTheater } from "./CommandTheater";
import { detectWebGLAvailability } from "./webgl-support";

vi.mock("next/dynamic", () => ({
  default: () =>
    function MockTheater3D({ onFallback }: { onFallback: () => void }) {
      return (
        <div data-testid="mock-3d-theater">
          <button type="button" onClick={onFallback}>simulate WebGL failure</button>
          3D scene mounted
        </div>
      );
    },
}));

vi.mock("./webgl-support", () => ({
  detectWebGLAvailability: vi.fn(),
}));

describe("CommandTheater", () => {
  beforeEach(() => {
    vi.mocked(detectWebGLAvailability).mockReturnValue(false);
  });

  it("starts with the 2D relationship map and keeps it available without WebGL", async () => {
    render(<CommandTheater />);

    expect(screen.getByRole("img", { name: /2D intelligence relationship map/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "2D map" })).toHaveAttribute("aria-pressed", "true");

    const threeDButton = screen.getByRole("button", { name: "3D theater" });
    await waitFor(() => expect(threeDButton).toBeDisabled());
    expect(screen.getByRole("status")).toHaveTextContent(/3D is unavailable/i);
    expect(screen.queryByTestId("mock-3d-theater")).not.toBeInTheDocument();
  });

  it("loads the 3D module only after the user opts into the 3D view", async () => {
    vi.mocked(detectWebGLAvailability).mockReturnValue(true);
    render(<CommandTheater />);

    const threeDButton = screen.getByRole("button", { name: "3D theater" });
    await waitFor(() => expect(threeDButton).toBeEnabled());
    expect(screen.queryByTestId("mock-3d-theater")).not.toBeInTheDocument();

    fireEvent.click(threeDButton);
    expect(await screen.findByTestId("mock-3d-theater")).toBeInTheDocument();
  });

  it("returns to the 2D map and reports unavailable graphics after a runtime canvas failure", async () => {
    vi.mocked(detectWebGLAvailability).mockReturnValue(true);
    render(<CommandTheater />);

    const threeDButton = screen.getByRole("button", { name: "3D theater" });
    await waitFor(() => expect(threeDButton).toBeEnabled());
    fireEvent.click(threeDButton);
    fireEvent.click(await screen.findByRole("button", { name: "simulate WebGL failure" }));

    expect(screen.getByRole("img", { name: /2D intelligence relationship map/i })).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(/3D is unavailable/i);
  });

  it("applies Arabic and Persian language direction and local labels", () => {
    render(<CommandTheater locale="ar" />);

    const main = screen.getByRole("main");
    expect(main).toHaveAttribute("dir", "rtl");
    expect(screen.getByRole("heading", { name: "مسرح قيادة الاستخبارات" })).toBeInTheDocument();

    fireEvent.change(screen.getByRole("combobox", { name: "لغة الواجهة" }), {
      target: { value: "fa" },
    });

    expect(main).toHaveAttribute("lang", "fa");
    expect(main).toHaveAttribute("dir", "rtl");
    expect(screen.getByRole("heading", { name: "تالار فرماندهی اطلاعات" })).toBeInTheDocument();
  });
});
