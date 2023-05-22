const express = require('express');
const path = require('path');

const app = express();
const port = 3000;

// Configurar o uso de arquivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Rota para a página inicial
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Rota para a página de login
app.post('/login', (req, res) => {
  res.redirect('/pages/principalPage.html');
});

// Iniciar o servidor
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});