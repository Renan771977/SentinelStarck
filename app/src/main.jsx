import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { ToastProvider } from "./lib/toast";
import { DialogProvider } from "./lib/dialog";
import { ThemeProvider } from "./lib/useTheme";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <ThemeProvider>
      <ToastProvider>
        <DialogProvider>
          <App />
        </DialogProvider>
      </ToastProvider>
    </ThemeProvider>
  </React.StrictMode>,
);