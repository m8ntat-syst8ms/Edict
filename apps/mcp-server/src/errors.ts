/** Tool-argument validation failure — rendered as an MCP isError text result. */
export class ToolInputError extends Error {
  readonly problems: string[];
  constructor(problems: string[]) {
    super(`invalid tool arguments:\n- ${problems.join('\n- ')}`);
    this.name = 'ToolInputError';
    this.problems = problems;
  }
}
