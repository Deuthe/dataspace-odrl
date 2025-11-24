const express = require('express');
const axios = require('axios');
const app = express();
app.use(express.json());

// 1. Policy Upload Endpoint (Unchanged)
app.post('/policies', async (req, res) => {
  const odrl = req.body;
  let constraints = '';
  // Extract constraints from ODRL JSON
  if (odrl.permission) {
    odrl.permission.forEach(p => {
      if (p.constraint) {
        p.constraint.forEach(c => {
          constraints += `    input.attributes["${c.leftOperand}"] == "${c.rightOperand}"\n`;
        });
      }
    });
  }

  // Build Rego Policy
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
    // Push to OPA
    await axios.put(
      'http://opa:8181/v1/policies/eindhoven',
      rego,
      { headers: { 'Content-Type': 'text/plain' } }
    );
    console.log("Policy updated successfully");
    res.json({ success: true, status: "Policy Active" });
  } catch (e) {
    console.error("OPA Error:", e.message);
    res.status(500).json({ error: "Failed to update policy engine" });
  }
});

// 2. Data Access Endpoint (UPDATED)
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
    // Step A: Ask OPA for permission
    const opaResp = await axios.post('http://opa:8181/v1/data/httpauthz/allow', { input });
    
    if (opaResp.data.result === true) {
      // Step B: Access Granted - Fetch JSON Data
      // Note: We now fetch data.json, not the root /
      const mockResp = await axios.get('http://mock-data/data.json');
      
      // Step C: Return clean JSON
      res.json(mockResp.data);
    } else {
      // Step D: Access Denied
      res.status(403).json({ 
        error: "Access Denied", 
        reason: "ODRL Policy constraints not met." 
      });
    }
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ error: "Internal System Error" });
  }
});

app.listen(3000, () => console.log('PAP Service running on port 3000'));
