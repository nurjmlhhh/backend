import { pool } from "../database.js";
import express from "express";
import cors from 'cors';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';


const app = express();
app.use(express.json()); //memparsing JSON request body
app.use(
    cors({
        origin: ["http://localhost:5173"],
        credentials: true
    })
);

// Endpoint untuk Registrasi
app.post("/api/register", async (req, res) => {
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

        const user = result.rows[0];

        // Generate JWT token
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, process.env.SECRET_KEY, {
            expiresIn: '1h', 
        });

        // Set token as HTTP-only cookie
        res.cookie('token', token, {
            httpOnly: true, // The cookie is inaccessible to JavaScript (prevents XSS attacks)
            secure: process.env.NODE_ENV === 'production', // Send cookie over HTTPS only in production
            maxAge: 60 * 60 * 1000, // 1 hour
            sameSite: 'strict', // Prevent CSRF attacks
        });

        res.status(201).send("Registrasi berhasil");
    } catch (error) {
        console.error(error);
        res.status(500).send(`Terjadi kesalahan saat registrasi: ${error.message}`);
    }
});


// Middleware untuk Autentikasi Token
function authenticateToken(req, res, next) {
    const authorization = req.headers.authorization;
    if (authorization && authorization.startsWith("Bearer ")) {
      const token = authorization.split(" ")[1];
      try {
        req.user = jwt.verify(token, process.env.SECRET_KEY);
        next();
      } catch (error) {
        res.status(401).send("Token tidak valid.");
      }
    } else {
      res.status(401).send("Anda belum login (tidak ada otorisasi).");
    }
}

// Middleware untuk Verifikasi Teacher
function authenticateTeacher(req, res, next) {
    if (req.user.role === 'teacher') {
      next();
    } else {
      res.status(403).send("Hanya teacher yang bisa menambahkan kelas");
    }
}

// Endpoint untuk Login
app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);

        if (result.rows.length > 0) {
            const user = result.rows[0];

            if (await argon2.verify(user.password, password)) {
                const token = jwt.sign(
                    { id: user.id, role: user.role }, 
                    process.env.SECRET_KEY, 
                    { expiresIn: '1h' }
                );
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



// function authenticateTeacher(req, res, next) {
//     if (req.user.role === 'teacher') {
//       next();
//     } else {
//       res.status(403).send("Hanya teacher yang bisa menambahkan kelas");
//     }
//   }


//---------------------------------MANIPULASI CLASS---------------------------------
// app.post("/api/class", async (req, res) =>{
//     const result = await pool.query(
//         "INSERT INTO class (name, kode) VALUES ($1, $2) RETURNING *",
//         [req.body.name, req.body.kode]
//     );
//     res.json(result.rows[0]);
// });

app.post("/api/class", authenticateToken, authenticateTeacher,async (req, res) => {
    const { name, kode, id_teacher } = req.body;
    const idTeacher = id_teacher; // Mengambil id_teacher dari token JWT

    try {
        const result = await pool.query(
            "INSERT INTO class (name, kode, id_teacher) VALUES ($1, $2, $3) RETURNING *",
            [name, kode, idTeacher]
        );
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error inserting class:', error);
        res.status(500).send("Terjadi kesalahan saat menambahkan kelas.");
    }
});

app.get("/api/class/:id", authenticateToken, authenticateTeacher, async (req, res) => {
    const result = await pool.query("SELECT * FROM class where id_teacher=$1", [req.params.id]);
    res.json(result.rows);
});

// app.put("/api/class/:id", authenticateToken, authenticateTeacher, async (req, res) => {
//     await pool.query(
//         "UPDATE class SET name = $1, kode = $2 WHERE id = $3",
//         [req.body.name, req.body.kode, req.params.id]
//     );
//     res.json("Class berhasil di update");
// });

app.put("/api/class/:id", authenticateToken, async (req, res) => {
    try {
        const { name, kode } = req.body;
        const { id } = req.params;

        await pool.query(
            "UPDATE class SET name = $1, kode = $2 WHERE id = $3",
            [name, kode, id]
        );

        res.status(200).json({ message: "Class berhasil diupdate" });
    } catch (error) {
        console.error("Error updating class:", error.message);
        res.status(500).json({ error: "Gagal memperbarui class" });
    }
});



// app.delete("/api/class/:id", authenticateToken, authenticateTeacher, async (req, res) => {
//     await pool.query("DELETE FROM class WHERE id = $1", [req.params.id]);
//     res.send("Class berhasil dihapus");
//   });

app.delete("/api/class/:id", authenticateToken, authenticateTeacher, async (req, res) => {
    const client = await pool.connect(); // Menggunakan client untuk transaksi

    try {
        const { id } = req.params;

        await client.query("BEGIN"); // Memulai transaksi

        // Hapus semua tasks yang terkait dengan kelas
        await client.query("DELETE FROM task WHERE id_class = $1", [id]);

        // Hapus semua posts yang terkait dengan kelas
        await client.query("DELETE FROM post WHERE id_class = $1", [id]);

        // Hapus kelas itu sendiri
        await client.query("DELETE FROM class WHERE id = $1", [id]);

        await client.query("COMMIT"); // Commit transaksi jika semua berhasil

        res.status(200).json({ message: "Class dan semua data terkait berhasil dihapus" });
    } catch (error) {
        await client.query("ROLLBACK"); // Rollback transaksi jika terjadi error
        console.error("Error deleting class and related data:", error.message);
        res.status(500).json({ error: "Gagal menghapus class dan data terkait" });
    } finally {
        client.release(); // Pastikan client dirilis setelah transaksi selesai
    }
});

//---------------------------------MANIPULASI Post---------------------------------

  app.post("/api/post", authenticateToken ,async (req, res) => {
    const { deskripsi, id_class } = req.body;
    const idClass = id_class; // Mengambil id_teacher dari token JWT

    try {
        const result = await pool.query(
            "INSERT INTO post (deskripsi, id_class) VALUES ($1, $2) RETURNING *",
            [deskripsi, idClass]
        );
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error inserting post:', error);
        res.status(500).send("Terjadi kesalahan saat menambahkan kelas.");
    }
});

  


app.get("/api/posts/:id", authenticateToken,async (req, res) => {
    const result = await pool.query("SELECT * FROM post where id_class=$1", [req.params.id]);
    res.json(result.rows);
});

app.put("/api/post/:id", authenticateToken, async (req, res) => {
    await pool.query(
        "UPDATE post SET deskripsi = $1 WHERE id = $2",
        [req.body.deskripsi, req.params.id]
    );
    res.json("post berhasil di update");
});



app.delete("/api/post/:id", authenticateToken, async (req, res) => {
    await pool.query("DELETE FROM post WHERE id = $1", [req.params.id]);
    res.send("post berhasil dihapus");
  });
  

//---------------------------------MANIPULASI TASK---------------------------------
// app.post("/api/task", async (req, res) =>{
//     const result = await pool.query(
//         "INSERT INTO task (title, deskripsi, deadline, id_class) VALUES ($1, $2, $3) RETURNING *",
//         [req.body.title, req.body.deskripsi, req.body.deadline]
//     );
//     res.json(result.rows[0]);
// });

app.post("/api/task", authenticateToken ,async (req, res) => {
    const { title, deskripsi, deadline, id_class } = req.body;
    const idClass = id_class; // Mengambil id_teacher dari token JWT

    try {
        const result = await pool.query(
            "INSERT INTO task (title, deskripsi, deadline, id_class) VALUES ($1, $2, $3, $4) RETURNING *",
            [title, deskripsi, deadline, idClass]
        );
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error inserting post:', error);
        res.status(500).send("Terjadi kesalahan saat menambahkan kelas.");
    }
});


app.get("/api/task/:id", async (req, res) => {
    const result = await pool.query("SELECT * FROM task WHERE id_class=$1", [req.params.id]);
    res.json(result.rows);
});

app.put("/api/task/:id", async (req, res) => {
    await pool.query(
        "UPDATE task SET title = $1, deskripsi = $2, deadline = $3 WHERE id = $4",
        [req.body.title, req.body.deskripsi, req.body.deadline, req.params.id]
    );
    res.send("task berhasil di update");
});

app.delete("/api/task/:id", async (req, res) => {
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

//---------------------------------MANIPULASI POSTINGAN---------------------------------
// app.post("/api/add-post", authenticateToken, async (req, res) =>{
//     const result = await pool.query(
//         "INSERT INTO post (deskripsi) VALUES ($1) RETURNING *",
//         [req.body.deskripsi]
//     );
//     res.json(result.rows[0]);
// });


// app.get("/api/post", async (req, res) => {
//     const result = await pool.query("SELECT * FROM post");
//     res.json(result.rows);
// });

// app.put("/api/update-post/:id", async (req, res) => {
//     await pool.query(
//         "UPDATE post SET deskripsi = $1 WHERE id = $3",
//         [req.body.deskripsi, req.params.id]
//     );
//     res.send("post berhasil di update");
// });



// app.delete("/api/delete-post/:id", async (req, res) => {
//     await pool.query("DELETE FROM post WHERE id = $1", [req.params.id]);
//     res.send("post berhasil dihapus");
//   });
  












app.listen(3000, () => console.log("Server berhasil dijalankan"));

