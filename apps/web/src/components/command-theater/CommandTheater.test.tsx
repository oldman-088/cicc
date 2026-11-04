import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CommandTheater } from "./CommandTheater";
import { detectWebGLAvailability } from "./webgl-support";

const theaterMock = vi.hoisted(() => ({ throwsOnRender: false }));

vi.mock("next/dynamic", () => ({
  default: () =>
    function MockTheater3D({ onFallback }: { onFallback: () => void }) {
      if (theaterMock.throwsOnRender) throw new Error("3D chunk initialization failed");
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
    theaterMock.throwsOnRender = false;
    vi.mocked(detectWebGLAvailability).mockReturnValue(false);
  });

  it("starts with the 2D relationship map and keeps it available without WebGL", async () => {
    render(<CommandTheater />);

    expect(screen.getByRole("img", { name: /2D intelligence relationship map/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "2D map" })).toHaveAttribute("aria-pressed", "true");

    const threeDButton = screen.getByRole("button", { name: "3D theater" });
    await waitFor(() => expect(threeDButton).toBeDisabled());
    expect(screen.getByText(/3D is unavailable/i)).toBeInTheDocument();
    expect(screen.queryByTestId("mock-3d-theater")).not.toBeInTheDocument();
  });

  it("labels fixtures as synthetic and confidence scores as illustrative, not verified intelligence", () => {
    render(<CommandTheater />);

    expect(screen.getAllByText(/Synthetic sample only · no live feeds or verified evidence connected/i).length).toBeGreaterThan(0);
    expect(screen.getByText("Synthetic UI fixture")).toBeInTheDocument();
    expect(screen.getAllByText(/illustrative only/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/No verified evidence attached/i).length).toBeGreaterThan(0);
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
    expect(screen.getByText(/3D is unavailable/i)).toBeInTheDocument();
  });

  it("falls back to the 2D map if the lazy 3D scene throws during initialization", async () => {
    vi.mocked(detectWebGLAvailability).mockReturnValue(true);
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    render(<CommandTheater />);

    const threeDButton = screen.getByRole("button", { name: "3D theater" });
    await waitFor(() => expect(threeDButton).toBeEnabled());
    theaterMock.throwsOnRender = true;
    fireEvent.click(threeDButton);

    expect(screen.getByRole("img", { name: /2D intelligence relationship map/i })).toBeInTheDocument();
    expect(screen.getByText(/3D is unavailable/i)).toBeInTheDocument();
    consoleError.mockRestore();
  });

  it("applies Arabic and Persian language direction and local labels", () => {
    render(<CommandTheater locale="ar" />);

    const main = screen.getByRole("main");
    expect(main).toHaveAttribute("dir", "rtl");
    expect(screen.getByRole("heading", { name: "مسرح قيادة الاستخبارات" })).toBeInTheDocument();
    expect(screen.getAllByText(/توضيحية فقط/).length).toBeGreaterThan(0);

    fireEvent.change(screen.getByRole("combobox", { name: "لغة الواجهة" }), {
      target: { value: "fa" },
    });

    expect(main).toHaveAttribute("lang", "fa");
    expect(main).toHaveAttribute("dir", "rtl");
    expect(screen.getByRole("heading", { name: "تالار فرماندهی اطلاعات" })).toBeInTheDocument();
    expect(screen.getAllByText(/صرفاً نمایشی/).length).toBeGreaterThan(0);
  });
});
