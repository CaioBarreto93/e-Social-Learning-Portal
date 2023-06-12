require('dotenv').config()
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')
const path = require('path');


const app = express();
const port = 3000;

// Credencials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

// Config JSON response
app.use(express.json())

// Models
const User = require('./models/User')

// Configurar o uso de arquivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Rota para a página inicial
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '/pages/index.html'));
});

// Routa para testar o token
app.get('/user/:id', checkToken, async (req, res)=>{
  const id = req.params.id

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
    )

    res.status(200).json({ msg: 'Autenticação realizada com Sucesso!', token})
    
  } catch (error) {

    console.log(error)

    return res.status(500).json({ msg: "Aconteceu um erro no servidor, tente novamente mais tarde."})
    
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