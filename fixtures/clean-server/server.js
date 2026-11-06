'use strict';

// Clean demo MCP server used as the MCPLens "known good" fixture.
// It exposes two harmless tools, keeps all data in memory, reads one
// non-secret environment variable, and touches no files and no network.

const greeting = process.env.MCPLENS_DEMO_GREETING || 'hello';

const tools = [
  {
    name: 'add',
    description: 'Add two numbers and return the sum. Inputs are the numbers a and b.',
    inputSchema: {
      type: 'object',
      properties: { a: { type: 'number' }, b: { type: 'number' } },
      required: ['a', 'b'],
    },
  },
  {
    name: 'greet',
    description: 'Return a short greeting for the given name.',
    inputSchema: {
      type: 'object',
      properties: { name: { type: 'string' } },
      required: ['name'],
    },
  },
];

function callTool(name, args) {
  if (name === 'add') return { content: [{ type: 'text', text: String(args.a + args.b) }] };
  if (name === 'greet') return { content: [{ type: 'text', text: `${greeting}, ${args.name}` }] };
  throw new Error(`Unknown tool: ${name}`);
}

module.exports = { tools, callTool };

if (require.main === module) {
  console.log(JSON.stringify({ tools: tools.map((t) => t.name) }));
}
