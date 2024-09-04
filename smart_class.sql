DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS class;
DROP TABLE IF EXISTS task;
DROP TABLE IF EXISTS post;

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(50),
    username VARCHAR(50),
    password VARCHAR(300)
);

CREATE TABLE class (
    id serial PRIMARY KEY,
    name varchar(50),
    kode varchar(50),
    id_teacher int,
    FOREIGN KEY (id_teacher) REFERENCES users(id)
);

create table post(
	id serial primary key,
	deskripsi text,
	id_class INT references class(id)
);


create table task(
	id serial primary key,
	title varchar(50),
	deskripsi text,
	deadline DATE,
	id_class INT references class(id)	
);
