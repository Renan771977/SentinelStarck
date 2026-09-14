import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

/**
 * Tema ativo: aplica, persiste e informa quem precisa reagir.
 *
 * A troca em si é uma linha — `document.documentElement.dataset.theme = x` — e
 * o navegador reavalia todas as variáveis CSS sozinho. Nenhum componente
 * precisa re-renderizar para mudar de cor.
 *
 * O contexto existe por um motivo específico: xterm e uPlot pintam em CANVAS e
 * não entendem `var(--x)`. Eles leem a cor resolvida uma vez, na criação. Então
 * precisam saber QUANDO o tema mudou para relerem. É só para isso que este
 * provider expõe o nome do tema — usar como dependência de efeito.
 */

export const THEMES = [
  {
    id: "cyberpunk",
    name: "Cyberpunk Enterprise",
    description: "O original: ciano neon e roxo sobre quase preto.",
    swatch: ["#090c12", "#00c2ff", "#7c3aed", "#35d07f"],
  },
  {
    id: "cyberpunk2077",
    name: "Cyberpunk 2077",
    description: "Amarelo ácido, ciano e carmim. Alto contraste.",
    swatch: ["#08080a", "#fcee0a", "#02d7f2", "#ff2e63"],
  },
  {
    id: "dracula",
    name: "Dracula",
    description: "Roxo e rosa sobre cinza-azulado. Clássico do VSCode.",
    swatch: ["#282a36", "#bd93f9", "#ff79c6", "#50fa7b"],
  },
  {
    id: "onedark",
    name: "One Dark",
    description: "Azul acinzentado, contraste moderado.",
    swatch: ["#282c34", "#61afef", "#c678dd", "#98c379"],
  },
  {
    id: "nord",
    name: "Nord",
    description: "Frio e sóbrio. O mais confortável para turno longo.",
    swatch: ["#2e3440", "#88c0d0", "#b48ead", "#a3be8c"],
  },
  {
    id: "light",
    name: "Claro",
    description: "Para sala iluminada e para relatório impresso.",
    swatch: ["#ffffff", "#0969da", "#8250df", "#1a7f37"],
  },
];

const DEFAULT_THEME = "cyberpunk";
const SETTING_KEY = "ui.theme";

const ThemeContext = createContext({ theme: DEFAULT_THEME, setTheme: () => {}, themes: THEMES });

export function useTheme() {
  return useContext(ThemeContext);
}

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(DEFAULT_THEME);

  // Aplica o tema no documento. Único ponto que mexe no DOM por causa de cor.
  const apply = useCallback((id) => {
    document.documentElement.dataset.theme = id;
  }, []);

  // Carrega a escolha salva. Até chegar, o CSS já mostra o tema padrão, então
  // não há flash de tema errado — só uma possível troca única na abertura.
  useEffect(() => {
    let alive = true;
    invoke("setting_get", { key: SETTING_KEY })
      .then((saved) => {
        if (!alive) return;
        const id = THEMES.some((t) => t.id === saved) ? saved : DEFAULT_THEME;
        setThemeState(id);
        apply(id);
      })
      .catch(() => apply(DEFAULT_THEME));
    return () => { alive = false; };
  }, [apply]);

  const setTheme = useCallback((id) => {
    if (!THEMES.some((t) => t.id === id)) return;
    setThemeState(id);
    apply(id);
    // Persiste sem bloquear a troca: a cor já mudou, salvar é assíncrono.
    invoke("setting_set", { key: SETTING_KEY, value: id }).catch(() => {});
  }, [apply]);

  return (
    <ThemeContext.Provider value={{ theme, setTheme, themes: THEMES }}>
      {children}
    </ThemeContext.Provider>
  );
}