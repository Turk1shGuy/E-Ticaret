CREATE TABLE IF NOT EXISTS users
(
    uid INTEGER PRIMARY KEY AUTOINCREMENT,
    uname VARCHAR(255) UNIQUE,
    pass VARCHAR(255)
);

INSERT INTO users (uname, pass) VALUES
('admin', 'admin'),
('test', 'test'),
('john_doe', 'password123'),
('jane_smith', 'securepass456'),
('michael_brown', 'mike2025'),
('emily_davis', 'emily@789'),
('chris_jones', 'chris!pass'),
('sarah_wilson', 'sarah#2025'),
('david_clark', 'david$secure'),
('linda_martin', 'linda*pass'),
('robert_lee', 'robert@lee'),
('patricia_white', 'patricia#white');


CREATE TABLE IF NOT EXISTS cart
(
--    id INTEGER PRIMARY KEY AUTOINCREMENT, -- for now this is bad
    user_id INT NOT NULL,
    product_id INT NOT NULL
);

INSERT INTO cart (user_id, product_id) VALUES
(1, 1),
(1, 2),
(1, 3),
(1, 4),
(1, 5),
(1, 6);
