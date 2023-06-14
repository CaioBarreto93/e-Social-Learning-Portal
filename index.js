require('dotenv').config()
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

// Utils
const { sendPasswordResetEmail } = require('./utils/email');

// Models
const User = require('./models/User')
const PasswordResetToken = require('./models/PasswordResetToken')


// Credencials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

// Config JSON response
const app = express();
const port = 3000;
app.use(express.json())

// Configurar o uso de arquivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Rota para a página inicial
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '/pages/index.html'));
});

app.get('/esqueceusenha', (req, res) => {
  res.sendFile(path.join(__dirname, '/pages/esqueceuSenha.html'));
});

// Rota para a pagina de formulario
app.get('/form-xml', (req, res) => {
  res.sendFile(path.join(__dirname, '/pages/formXml.html'));
});
// Rota para solicitar recuperação de senha
app.post('/password-reset', async (req, res) => {
  const { email } = req.body;

  try {
    // Verificar se o email existe na base de dados
    const user = await User.findOne({ email: email });
    if (!user) {
      return res.status(404).json({ msg: 'Usuário não encontrado' });
    }

    // Gerar um token único para a recuperação de senha
    const token = uuidv4();

    // Criar um registro do token no banco de dados
    const passwordResetToken = new PasswordResetToken({
      user: user._id,
      token,
      expiresAt: Date.now() + 60 * 60 * 1000, // Expira em 1 hora
    });
    await passwordResetToken.save();

    // Enviar o email com o link de recuperação de senha
    sendPasswordResetEmail(email, token);

    res.status(200).json({ msg: 'Email de recuperação de senha enviado' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: 'Ocorreu um erro no servidor' });
  }
});

app.post('/password-reset/reset', async (req, res) => {
  const { token, password } = req.body;

  try {
    // Verificar se o token de recuperação existe e ainda é válido
    const passwordResetToken = await PasswordResetToken.findOne({ token });
    if (!passwordResetToken) {
      return res.status(400).json({ msg: 'Token de recuperação inválido ou expirado' });
    }
    if(passwordResetToken.expiresAt < Date.now()){
      await PasswordResetToken.deleteOne({_id:passwordResetToken.id});
      return res.status(400).json({ msg: 'Token de recuperação inválido ou expirado' });
    }

    if(!password){
      return res.status(404).json({msg: "A senha é obrigatoria!"});
    }

    // Encontrar o usuário associado ao token
    const user = await User.findById(passwordResetToken.user);
    if (!user) {
      return res.status(404).json({ msg: 'Usuário não encontrado' });
    }

    // Hash da nova senha
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Atualizar a senha do usuário
    user.password = hashedPassword;
    await user.save();

    // Remover o token de recuperação de senha utilizado
    await PasswordResetToken.deleteOne({_id:passwordResetToken.id});

    res.status(200).json({ msg: 'Senha redefinida com sucesso' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: 'Ocorreu um erro no servidor' });
  }
});

// Rota para redirecionar o usuário autenticado para a página principal
app.get('/pagina-principal', (req, res) => {
  res.sendFile(path.join(__dirname, '/pages/principalPage.html'));
});

//Routa para validar token
app.post('/valida/token', async (req,res) =>{
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(" ")[1]

  if(!token){
    return res.status(401).json({msg: 'Acesso negado!'})
  }

  try {
    const secret = process.env.SECRET

    jwt.verify(token, secret)

    return res.status(200).json({msg:"Token valido"});
    
  } catch (error) {
    return res.status(400).json({msg:"Token inválido ou expirado!"})
  }
});

// Routa para testar o token
app.post('/user', checkToken, async (req, res)=>{
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(" ")[1]
  const decode =jwt.decode(token) 
  const id = decode.id;

  //Verificar se existe o usuário
  const user = await User.findById(id, '-password')

  if(!user){
    return res.status(404).json({ msg: 'Usuário não encontrado'})
  }

  res.status(200).json({ user })
})

// Registro de usuário
app.post('/auth/register', async (req,res)=>{
  const { name, email, password, confirmpassword } = req.body

  // validações
  if(!name){
    return res.status(422).json({ msg: 'O nome é obrigatório!'})
  }

  if(!email){
    return res.status(422).json({ msg: 'O email é obrigatório!'})
  }

  if(!password){
    return res.status(422).json({ msg: 'A senha é obrigatória!'})
  }

  if(password !== confirmpassword){
    return res.status(422).json({ msg: 'As senhas não conferem!'})
  }

  // Verificar se e-mail existe
  const userExists = await User.findOne({ email: email})

  if(userExists){
    return res.status(422).json({ msg: 'Por favor, utilize outro e-mail!'})
  }

  // create password
  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  //create user 
  const user = new User({
    name,
    email,
    password: passwordHash,
  })

  try {

    await user.save()

    return res.status(201).json({msg:"Usuário cadastrado com sucesso!"})
    
  } catch (error) {

    console.log(error)

    return res.status(500).json({ msg: "Aconteceu um erro no servidor, tente novamente mais tarde."})
    
  }
});

// Atualiza o User com o seu novo avatar em base64
app.post('/user/update-avatar', checkToken, async (req,res)=>{
  const { id, avatar } = req.body

  try {
    // Encontrar o usuário pelo ID
    const user = await User.findById(id);

    if(!user){
      return res.status(404).json({msg:"Usuário não encontrado"});
    }

    user.avatar = avatar;

    await user.save();
    res.status(200).json({msg:"Avatar atualizando com sucesso"})
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: 'Ocorreu um erro no servidor' });
  }
});

//Verificar o Token
function checkToken(req, res, next){

  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(" ")[1]

  if(!token){
    return res.status(401).json({msg: 'Acesso negado!'})
  }

  try {
    const secret = process.env.SECRET

    jwt.verify(token, secret)

    next()
    
  } catch (error) {
    return res.status(400).json({msg:"Token inválido!"})
  }
}

// Login User
app.post("/auth/login", async (req,res)=>{
  
  const {email, password} = req.body

  //validações
  if(!email){
    return res.status(422).json({ msg: 'O email é obrigatório!'})
  }

  if(!password){
    return res.status(422).json({ msg: 'A senha é obrigatória!'})
  }

  //Verificar se existe o email
  const user = await User.findOne({ email: email})

  if(!user){
    return res.status(404).json({ msg: 'Usuário não encontrado!'})
  }

  //Verifica se o password está correto
  const checkPassword = await bcrypt.compare(password, user.password)

  if(!checkPassword){
    return res.status(422).json({ msg: 'Senha inválida!'})
  }

  try {

    const secret = process.env.SECRET

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret,
      { expiresIn: '1h'}
    )

    res.status(200).json({ msg: 'Autenticação realizada com Sucesso!', token})
    
  } catch (error) {

    console.log(error)

    return res.status(500).json({ msg: "Erro ao gerar o Token, tente novamente mais tarde."})
    
  }
})

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@clustertcc.nos70pw.mongodb.net/tccDatabase?retryWrites=true&w=majority`,
  ).then(()=>{
    // Iniciar o servidor
    app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});
  })