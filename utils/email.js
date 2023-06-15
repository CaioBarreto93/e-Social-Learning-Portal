require('dotenv').config();
const sgMail = require('@sendgrid/mail');

async function sendPasswordResetEmail(email, token) {
  // Configurar o transporte de email
  sgMail.setApiKey(process.env.SEND_API_KEY);

  // Configurar o email a ser enviado
  const msg = {
    to: email,
    from: 'caio.l.barreto@ba.estudante.senai.br',
    subject: 'Recuperação de senha',
    text: `Você solicitou a recuperação de senha. Segue o token para resetar sua senha: ${token}`,
    html: `<strong>Você solicitou a recuperação de senha. Segue o token para resetar sua senha: ${token}</strong>`,
  };

  // Enviar o email
  try {
    await sgMail.send(msg);
    
  } catch (error) {

    console.error(error)
    
  }
}

module.exports = {
    sendPasswordResetEmail,
  };
