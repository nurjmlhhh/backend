import { pool } from "../database.js";
import express from "express";
import cors from 'cors';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';


const app = express();
app.use(express.json()); //memparsing JSON request body
app.use(
    cors({
        origin: ["http://localhost:5173"]
    })
);

// app.post("/api/register", async (req, res) =>{
//     const hash = await argon2.hash(req.body.password);
//     await pool.query(
//         "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
//         [req.body.username, req.body.email, hash]
//     );
//     res.send("Registrasi berhasil");
// } );

app.post("/api/register", async (req, res) => {

    // Validate the role
    const validRoles = ['teacher', 'student'];
    if (!validRoles.includes(req.body.role)) {
        return res.status(400).send("Role tidak valid. Pilih antara 'teacher' atau 'student'.");
    }

    try {
        const hash = await argon2.hash(req.body.password);
        const result = await pool.query(
            "INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *",
            [req.body.username, req.body.email, hash, req.body.role]
        );
        res.status(201).send("Registrasi berhasil");
    } catch (error) {
        console.error(error);
        res.status(500).send(`Terjadi kesalahan saat registrasi: ${error.message}`);

    }
});

function authenticateToken(req, res, next){
    const authorization = req.headers.authorization;
    if(authorization && authorization.startsWith("Bearer ")){
        const token = authorization.split(" ")[1];
        try{
            req.user = jwt.verify(token, process.env.SECRET_KEY);
            next();
        }catch (error){
            res.status(401).send("Token tidak valid");
        }
    }else{
        res.status(401).send("Anda belum login");
    }
}

function authenticateTeacher(req, res, next) {
    if (req.user.role === 'teacher') {
      next();
    } else {
      res.status(403).send("Hanya teacher yang bisa menambahkan kelas");
    }
  }

app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);

        if (result.rows.length > 0) {
            const user = result.rows[0];

            if (await argon2.verify(user.password, password)) {
                const token = jwt.sign({ id: user.id, role: user.role }, process.env.SECRET_KEY, { expiresIn: '1h' });
                res.json({
                    token,
                    message: "Login berhasil",
                });
            } else {
                res.status(401).send("Kata sandi salah");
            }
        } else {
            res.status(404).send(`Pengguna dengan nama ${username} tidak ditemukan`);
        }
    } catch (error) {
        console.error('Terjadi kesalahan!', error);
        res.status(500).send("Terjadi kesalahan saat login.");
    }
});
//---------------------------------MANIPULASI CLASS---------------------------------
app.post("/api/add-class", authenticateToken, authenticateTeacher, async (req, res) =>{
    const result = await pool.query(
        "INSERT INTO class (name, kode) VALUES ($1, $2) RETURNING *",
        [req.body.name, req.body.kode]
    );
    res.json(result.rows[0]);
});


app.get("/api/class", async (req, res) => {
    const result = await pool.query("SELECT * FROM class");
    res.json(result.rows);
});

app.put("/api/update-class/:id", async (req, res) => {
    await pool.query(
        "UPDATE class SET name = $1, kode = $2 WHERE id = $3",
        [req.body.name, req.body.kode, req.params.id]
    );
    res.send("Class berhasil di update");
});



app.delete("/api/delete-class/:id", async (req, res) => {
    await pool.query("DELETE FROM class WHERE id = $1", [req.params.id]);
    res.send("Class berhasil dihapus");
  });
  

//---------------------------------MANIPULASI TASK---------------------------------
app.post("/api/add-task", async (req, res) =>{
    const result = await pool.query(
        "INSERT INTO task (title, deskripsi, deadline) VALUES ($1, $2, $3) RETURNING *",
        [req.body.title, req.body.deskripsi, req.body.deadline]
    );
    res.json(result.rows[0]);
});

app.get("/api/task", async (req, res) => {
    const result = await pool.query("SELECT * FROM task");
    res.json(result.rows);
});

app.put("/api/update-task/:id", async (req, res) => {
    await pool.query(
        "UPDATE task SET title = $1, deskripsi = $2, deadline = $3 WHERE id = $4",
        [req.body.title, req.body.deskripsi, req.body.deadline, req.params.id]
    );
    res.send("task berhasil di update");
});

app.delete("/api/detele-task/:id", async (req, res) => {
    await pool.query("DELETE FROM task WHERE id = $1", [req.params.id]);
    res.send("task berhasil di detele");
});


//---------------------------------MANIPULASI STUDENT---------------------------------
app.post("/api/add-student", async (req, res) =>{
    const result = await pool.query(
        "INSERT INTO enrollment (title, deskripsi, deadline) VALUES ($1, $2, $3) RETURNING *",
        [req.body.title, req.body.deskripsi, req.body.deadline]
    );
    res.json(result.rows[0]);
});

app.get("/api/student", async (req, res) => {
    const result = await pool.query("SELECT * FROM enrollment");
    res.json(result.rows);
});

// app.put("/api/update-task/:id", async (req, res) => {
//     await pool.query(
//         "UPDATE task SET title = $1, deskripsi = $2, deadline = $3 WHERE id = $4",
//         [req.body.title, req.body.deskripsi, req.body.deadline, req.params.id]
//     );
//     res.send("task berhasil di update");
// });

app.delete("/api/detele-student/:id", async (req, res) => {
    await pool.query("DELETE FROM enrollment WHERE id = $1", [req.params.id]);
    res.send("task berhasil di detele");
});













app.listen(3000, () => console.log("Server berhasil dijalankan"));

