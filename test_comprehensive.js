
// Comprehensive Security Test File - Contains multiple security issues

const express = require('express');
const md5 = require('md5');
const crypto = require('crypto');
const app = express();

// 1. UNSAFE: eval with user input
app.get('/execute', (req, res) => {
  const userInput = req.query.code;
  const result = eval(userInput); // DANGEROUS: eval with user input
  res.json({ result });
});

// 2. WEAK CRYPTO: MD5 usage
app.post('/hash', (req, res) => {
  const password = req.body.password;
  const hash = md5(password); // WEAK: MD5 is cryptographically broken
  res.json({ hash });
});

// 3. WEAK CRYPTO: SHA1 usage
app.post('/sha1', (req, res) => {
  const data = req.body.data;
  const hash = crypto.createHash('sha1').update(data).digest('hex'); // WEAK: SHA1 is broken
  res.json({ hash });
});

// 4. UNSANITIZED INPUT: Direct use of user input
app.get('/search', (req, res) => {
  const query = req.query.q;
  document.getElementById('results').innerHTML = query; // DANGEROUS: XSS vulnerability
  res.json({ query });
});

// 5. UNSANITIZED INPUT: Assignment to dangerous properties
app.post('/update', (req, res) => {
  const content = req.body.content;
  document.getElementById('content').outerHTML = content; // DANGEROUS: XSS vulnerability
  res.json({ success: true });
});

// 6. POOR ERROR HANDLING: Empty catch block
app.get('/api/data', async (req, res) => {
  try {
    const data = await fetchData();
    res.json(data);
  } catch (error) {
    // EMPTY: Poor error handling
  }
});

// 7. POOR ERROR HANDLING: Only console logging
app.get('/api/users', async (req, res) => {
  try {
    const users = await fetchUsers();
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error); // POOR: Only console logging
  }
});

// 8. POOR ERROR HANDLING: Promise.catch with empty handler
app.get('/api/config', (req, res) => {
  fetchConfig()
    .then(config => res.json(config))
    .catch(() => {}); // POOR: Empty error handler
});

// 9. UNSAFE: setTimeout with user input
app.post('/schedule', (req, res) => {
  const code = req.body.code;
  const delay = req.body.delay;
  setTimeout(code, delay); // DANGEROUS: Code injection via setTimeout
  res.json({ scheduled: true });
});

// 10. UNSAFE: Function constructor with user input
app.post('/dynamic', (req, res) => {
  const body = req.body.functionBody;
  const dynamicFunction = new Function(body); // DANGEROUS: Code injection
  const result = dynamicFunction();
  res.json({ result });
});

// 11. UNSANITIZED INPUT: Direct use of cookies
app.get('/profile', (req, res) => {
  const userId = document.cookie.split('=')[1]; // DANGEROUS: Unsanitized cookie access
  res.json({ userId });
});

// 12. UNSANITIZED INPUT: Direct use of localStorage
app.get('/preferences', (req, res) => {
  const theme = localStorage.getItem('theme'); // DANGEROUS: Unsanitized localStorage access
  res.json({ theme });
});

// Safe code for comparison
function safeFunction() {
  return 'This is safe';
}

function properErrorHandling() {
  try {
    // Some operation
    return 'success';
  } catch (error) {
    // Proper error handling
    logger.error('Operation failed', { error: error.message, stack: error.stack });
    throw new Error('Operation failed');
  }
}

function strongCrypto() {
  const crypto = require('crypto');
  const hash = crypto.createHash('sha256').update('password').digest('hex'); // STRONG: SHA256
  return hash;
}

module.exports = { app, safeFunction, properErrorHandling, strongCrypto };
