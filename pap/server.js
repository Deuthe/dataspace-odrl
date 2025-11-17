const express = require('express');
const axios = require('axios');
const app = express();
app.use(express.json());

app.post('/policies', async (req, res) => {
  const odrl = req.body;
  let constraints = '';
  odrl.permission?.forEach(p => {
    p.constraint?.forEach(c => {
      constraints += `    input.attributes["${c.leftOperand}"] == "${c.rightOperand}"\n`;
    });
  });

  const rego = [
    'package httpauthz',
    '',
    'default allow := false',
    '',
    'allow {',
    constraints.trim(),
    '    input.method == "GET"',
    '    startswith(input.path, "/data/")',
    '}'
  ].join('\n');

  try {
    await axios.put(
      'http://opa:8181/v1/policies/eindhoven',
      rego,
      { headers: { 'Content-Type': 'text/plain' } }
    );

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.response?.data || e.message });
  }
}); // <--- THIS CLOSES app.post('/policies')

app.get('/data/test', async (req, res) => {
  const input = {
    method: "GET",
    path: "/data/test",
    attributes: {
      role: req.headers['x-attributes-role'],
      gemeente: req.headers['x-attributes-gemeente']
    }
  };

  try {
    const opaResp = await axios.post('http://opa:8181/v1/data/httpauthz/allow', { input });
    if (opaResp.data.result) {
      const mockResp = await axios.get('http://mock-data/');
      res.set('Content-Type', 'text/html').send(mockResp.data);
    } else {
      res.status(403).send('Forbidden by ODRL policy');
    }
  } catch (e) {
    res.status(500).send('OPA error');
  }
});

app.listen(3000, () => console.log('PAP running'));
