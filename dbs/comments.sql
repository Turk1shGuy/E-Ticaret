CREATE TABLE IF NOT EXISTS comments (
    comid INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
    pid INTEGER NOT NULL, 
    uname TEXT NOT NULL, 
    cdate DATETIME NOT NULL, 
    comment TEXT NOT NULL
);

INSERT INTO comments (pid, uname, cdate, comment) VALUES
(1, "Anonymous", "2023-10-01 12:00:00", "This is a comment for product 1."),
(2, "admin", "2023-10-01 12:05:00", "This is a comment for product 2."),
(2, "john_doe", "2023-10-01 12:10:00", "This is another comment for product 2."),
(2, "jane_smith", "2023-10-01 12:15:00", "Yet another comment for product 2."),
(5, "michael_brown", "2023-10-01 12:20:00", "This is a comment for product 5.");
