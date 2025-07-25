import dotenv, { populate } from 'dotenv';
dotenv.config();
import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken';
import cors from 'cors'
import pkg from 'firebase-admin'; 
const admin = pkg;
import { getAuth } from 'firebase-admin/auth'
import serviceAccountKey from './react-js-blog-website-59a05-firebase-adminsdk-fbsvc-5a6ad8c693.json' assert { type: 'json' };
import { uploadProfileImg } from './utils/Cloudinary.js';
import { uploadBanner } from './utils/Cloudinary.js';

// schema below
import User from './Schema/User.js'
import Blog from './Schema/Blog.js'
import Notification from './Schema/Notification.js'
import Comment from './Schema/Comment.js'


const server = express();
let PORT =  5000;

// Middlewares
server.use(express.json());
server.use(cors());

admin.initializeApp({
    credential: admin.credential.cert(serviceAccountKey)
})
const auth = getAuth();
const messaging = admin.messaging();

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;


mongoose.connect(process.env.DB_LOCATION, { autoIndex: true })

const generateUsername = async (email) => {
    let username = email.split("@")[0];
    let isUsernameNotUnique = await User.exists({"personal_info.username": username});
    isUsernameNotUnique ? username += nanoid().substring(0, 5) : "";
    return username
}

const verifyJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({error: "No access token"})
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({error: "Access token is invalid"})
        }
        req.user = user.id
        next()
    })
}

const formateDataToSend = (user) => {
    const access_token = jwt.sign({id: user._id}, process.env.JWT_SECRET)
    return {
        access_token,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname: user.personal_info.fullname
    }
}

server.post("/signup", (req, res) => {
    console.log(" Received POST /signup request");

    let { fullname, email, password } = req.body;

    if (fullname.length < 3) {
        return res.status(403).json({ error: 'Fullname must be at least 3 letters long' });
    }
    if (!emailRegex.test(email)) {
        return res.status(403).json({ error: 'Invalid email format' });
    }
    if (password.length < 6) {
        return res.status(403).json({ error: 'Password must be at least 6 characters long' });
    }

    bcrypt.hash(password, 10, async (err, hashed_password) => {

        console.log("Password hashed successfully");

        let username = await generateUsername(email);

        let user = new User({
            personal_info: {fullname, email, password: hashed_password, username}
        })
        user.save()
        .then(u => {
            return res.status(200).json(formateDataToSend(u))
        })    
        .catch(err => {
                if (Number(err.code) === 11000) {
                    return res.status(400).json({ "error": "Email already exists." });
                }
            
                return res.status(500).json({ "error": err.message });
            });
    })
        
});

server.post("/signin", (req, res) => {
    let {email, password} = req.body;
    // Handle undefined or invalid email
    if (!email || typeof email !== "string") {
        return res.status(400).json({ error: "Valid email is required" });
    }

    User.findOne({"personal_info.email": email.toLowerCase()})
    .then((user) => {
        if (!user) {
            return res.status(403).json({ error: "Email not found" });
          }
        if (!user.google_auth) {
            bcrypt.compare(password, user.personal_info.password, (err, result) => {
            if (err) {
                return res.status(403).json({"error": "Error occured while login please try again"})
            }
            if (!result) {
                return res.status(403).json({"error": "Incorrect password" })
            } else{
                return res.status(200).json(formateDataToSend(user))
            }
        })
        }
        else {
            return res.status(403).json({"error": "Account was created with google try login with other google account."})
        }
    })
    .catch(err => {
        return res.status(500).json({ error: "Internal server error" });
    });
});

server.post("/google-auth", async (req, res) => {
    console.log("HIT: /google-auth");
    let { access_token } = req.body; 

    getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {
        let {email, name, picture} = decodedUser;
        picture = picture.replace("s96-c", "s-384-c")
        let user = await User.findOne({"personal_info.email": email}).select("personal_info.fullname personal_info.username google_auth").then((u) => {
            return u || null
        })
        .catch((err) => {
            return res.status(500).json({"error": err.message})
        })
        // sign up
        if (user) { 
            if (!user.google_auth) {
                return res.status(403).json({"error": "This email was signed up without google. Please log in with password to access the account."})
            }
        }
        // log in
        else {
            let username = await generateUsername(email);
            user = new User({
                personal_info: { fullname: name, email, username  },
                google_auth: true
            })
            await user.save().then((u) => {
                user = u;
            })
            .catch(err => {
                return res.status(500).json({"error": err.message})
            })
        }
        return res.status(200).json(formateDataToSend(user))

    })
    .catch(err => {
        return res.status(500).json({"error": err.message})
    })

});

server.post('/upload-banner', uploadBanner.single('banner'), (req, res) => {
  if (!req.file) {
    console.error('No file received in request');
    return res.status(400).json({ error: 'No file uploaded' }); 
  }
  return res.status(200).json({ url: req.file.path }); // req.file.path will be the Cloudinary URL
});

// server.post('/upload-banner', (req, res) => {
//   upload.single('banner')(req, res, (err) => {
//     if (err) {
//       console.error('Upload middleware error:', err);
//       return res.status(500).json({ error: err.message });
//     }
//     if (!req.file) {
//       console.error('No file received in request');
//       return res.status(400).json({ error: 'No file uploaded' }); 
//     }
//     console.log('File received:', req.file);
//     return res.status(200).json({ url: req.file.path });
//   });
// });

server.post('/create-blog', verifyJWT, (req, res) => {
    let authorId = req.user;
    
    let { title, des, banner, content, tags, id, draft } = req.body;
    
    draft = Boolean(draft);

    if (!title.length) {
        return res.status(403).json({ error: "You must provide a title" })
    }

    if (draft !== true) {
        if (!des.length || des.length > 1000) {
            return res.status(403).json({ error: "You must provide blog description under 200 characters" })
        }
        if (!banner.length) {
            return res.status(403).json({ error: "You must provide banner to publish it" })
        }
        if (!content.blocks.length) {
            return res.status(403).json({ error: "There must be some blog content to publish it " })
        }
        if (!tags.length || tags.length > 200) {
            return res.status(403).json({ error: "You must provide blog tag in order to publish the blog" })
        }
    }
    tags = tags.map(tag => tag.toLowerCase());
    
    let blog_id = id || title.replace(/[^a-zA-Z0-9]/g,' ').replace(/\s+/g, "-").trim() + nanoid();
    if (id) {
        Blog.findOneAndUpdate({blog_id}, {title, des, banner, content, tags, draft: draft ? draft: false})
        .then(() => {
                return res.status(200).json({id: blog_id})
            })
            .catch(err => {
                return res.status(500).json({error: err.message})
            })
    } else {
        let blog = new Blog ({
        title, des, banner, content, tags, author: authorId, blog_id, draft: Boolean(draft)
        })
        blog.save().then(blog => {
            let incrementVal = draft ? 0 : 1;
            User.findOneAndUpdate({ _id: authorId} ,{$inc: {"account_info.total_posts": incrementVal}, $push: { "blogs": blog._id}})
            .then(user => {
                return res.status(200).json({id: blog.blog_id})
            })
            .catch(err => {
                return res.status(500).json({error: err.message})
            })
        })
        .catch(err => {
            return res.status(500).json({error: err.message})
        })
    }
    

});

server.post('/latest-blogs', async (req, res) => {
    let { page } = req.body 
    const limit = 5;
    try {
        const blogs = await Blog.find({ draft: false })
            .populate({
                path: "author",
                model: "User", // Explicitly specify the correct model
                select: "personal_info -_id",
            })
            .sort({ publishedAt: -1 })
            .select("blog_id title des banner activity tags publishedAt -_id")
            .limit(limit)
            .skip((page - 1) * limit)
            .lean();

        const formattedBlogs = blogs.map(blog => ({
            ...blog,
            author: {
                profile_img: blog.author?.personal_info?.profile_img || null,
                username: blog.author?.personal_info?.username || null,
                fullname: blog.author?.personal_info?.fullname || null,
            },
        }));

        return res.status(200).json({ blogs: formattedBlogs });
    } catch (err) {
        console.error("Error:", err);
        return res.status(500).json({ error: "Failed to load blogs" });
    }
});


server.get("/trending-blogs", (req, res) => {
    Blog.find({draft: false})
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({"activity.total_reads": -1, "activity.total_likes": -1, "publishedAt": -1})
    .select("blog_id title publishedAt -_id")
    .limit(5)
    .then(blogs => {
        return res.status(200).json({blogs})

    })
    .catch(err => {
        console.log(err);
        return res.status(500).json({err: err.message})

    })
});

server.post('/all-latest-blogs-count', (req, res) => {
    Blog.countDocuments({draft: false})
    .then(count => {
        return res.status(200).json({totalDocs: count})
    })
    .catch(err => {
        console.log(err);
        return res.status(500).json({error: err.message});
    })
});

server.post("/search-blogs-count", (req, res) => {
    let { tag, author, query } = req.body;

    let findQuery;
    if (tag) {
        findQuery = { tags: tag, draft: false };
    } else if (query) {
        findQuery = { draft: false, title: new RegExp(query, 'i') }
    } else if (author) {
        findQuery = {author, draft: false}
    }

    Blog.countDocuments(findQuery)
    .then(count => {
        return res.status(200).json({ totalDocs: count })
    })
    .catch(err => {
        console.log(err)
        return res.status(500).json({ err: err.message})
    })
});

server.post('/search-blogs', (req, res) => {
    let { tag, query, author, page, limit, eliminate_blog } =  req.body;

    let findQuery;

    if (tag) {
        findQuery = { tags: tag, draft: false, blog_id: {$ne: eliminate_blog} };
    } else if (query) {
        findQuery = { draft: false, title: new RegExp(query, 'i') }
    } else if (author) {
        findQuery = {author, draft: false}
    }

    let maxLimit = limit ? limit : 2;

    Blog.find(findQuery)
    .populate("author","personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({"publishedAt": -1})
    .select("blog_id title des banner activity tags  publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(blogs => {
        return res.status(200).json({blogs})

    })
    .catch(err => {
        console.log(err);
        return res.status(500).json({err: err.message})

    })

});

server.post('/search-users', (req, res) => {
    let { query } = req.body;

    User.find({ "personal_info.username": new RegExp(query, 'i') })
    .limit(50)
    .select("personal_info.fullname personal_info.username personal_info.profile_img -_id")
    .then(users => {
        return res.status(200).json({ users })
    })
    .catch(err => {
        console.log(err);
        return res.status(500).json({ error: err.message })
    })
});

server.post('/get-profile', (req, res) => {
    let {username} = req.body;
    User.findOne({"personal_info.username": username})
    .select("-personal_info.password -google_auth -updatedAt -blogs")
    .then(user => {
        res.status(200).json(user);
    })
    .catch(err => {
        res.status(500).json({err: err.message})
    })
});

server.post('/get-blog', (req, res)=> {
    let {blog_id} = req.body;
    let incrementVal = 1;

    Blog.findOneAndUpdate({blog_id}, {$inc : {"activity.total_reads": incrementVal}})
    .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img")
    .select("title des content banner activity publishedAt blog_id tags")
    .then(blog => {
        const username = blog.author.personal_info.username;
        User.findOneAndUpdate({"personal_info.username": username}, {
            $inc : {"account_info.total_reads": incrementVal}
        })
        .catch(err => {
            return res.status(500).json({error: err.message});
        })
        return res.status(200).json({blog});
    })
    .catch(err => {
        return res.status(500).json({error: err.message});
    })
});

server.post('/like-blog', verifyJWT, (req, res) => {
    let user_id = req.user;
    let {_id, isLikedByUser} = req.body;
    let incrementVal = !isLikedByUser ? 1 : -1;
    Blog.findOneAndUpdate({_id}, {$inc: {"activity.total_likes": incrementVal}})
    .then(blog => {
        if (!isLikedByUser) {
            let like =  new Notification({
                type: 'like',
                blog: _id,
                notification_for: blog.author,
                user: user_id
            });
            like.save().then(notification => {
                return res.status(200).json({liked_by_user: true})
            })
        }
        else{
            Notification.findOneAndDelete({user: user_id, blog: _id, type: 'like'})
            .then(data => {
                return res.status(200).json({ liked_by_user: false })
            })
            .catch(err => {
                return res.status(500).json({err: err.message})
            })
        }
    })

});

server.post('/isliked-by-user', verifyJWT, (req, res) => {
    let user_id = req.user;
    let {_id} = req.body;
    Notification.exists({user: user_id, type: 'like', blog: _id})
    .then(result => {
        return res.status(200).json({ result });
    })
    .catch(err => {
        res.status(500).json({err: err.message});
    })

});

server.post('/add-comment', verifyJWT, (req, res) => {
    let user_id = req.user;

    let {_id, comment, blog_author, replying_to, notification_id} = req.body;

    if (!comment.length) {
        return res.status(403).json({error: "Please write something to leave a comment"});
    }
    let commentObj = {
        blog_id: _id, blog_author, comment, commented_by: user_id,
    }
    if (replying_to) {
        commentObj.parent = replying_to;
        commentObj.isReply = true
    }
    new Comment(commentObj).save().then(async commentFile => {
        let {comment, commentedAt, children} = commentFile;

        Blog.findOneAndUpdate({_id},{$push: {"comments": commentFile._id}, $inc:{"activity.total_comments": 1, "activity.total_parents_comments": replying_to ? 0 : 1}, })
        .then(blog => {console.log('new comment has been created')});
        let notificationObj = {
            type: replying_to ? "reply" : "comment",
            blog: _id,
            notification_for: blog_author,
            user: user_id,
            comment: commentFile._id
        }

        if (replying_to) {
            notificationObj.replied_on_comment = replying_to;

            await Comment.findOneAndUpdate({_id: replying_to}, {$push: {children: commentFile._id}})
            .then(replyingToCommentDoc => {notificationObj.notification_for = replyingToCommentDoc.commented_by})

            if (notification_id) {
                Notification.findOneAndUpdate({_id, notification_id}, {reply: commentFile._id})
                .then(notification => console.log("Notification updated"))
            }
        }


        new Notification(notificationObj).save().then(notification => console.log('new notification created'));
        return res.status(200).json({comment, commentedAt, _id: commentFile._id, user_id, children})
    })


});

server.post('/get-blog-comment', (req, res) => {
    let {blog_id, skip} = req.body;
    let maxLimit = 5;
    Comment.find({blog_id, isReply: false})
    .populate("commented_by", "personal_info.username personal_info.fullname personal_info.profile_img")
    .skip(skip)
    .limit(maxLimit)
    .sort({'commentedAt': -1})
    .then(comment => {
        return res.status(200).json(comment);
    })
    .catch(err => {
        console.log(err.message);
        return res.status(500).json({err: err.message});
    })
});

server.post('/get-replies', async (req, res) => {
    let { _id, skip } = req.body;
    let maxLimit = 5;
    skip = Number(skip) || 0;

    if (!_id) {
        return res.status(400).json({ error: "Missing comment ID" });
    }

    try {
        const doc = await Comment.findOne({ _id })
            .populate({
                path: "children",
                options: {
                    limit: maxLimit,
                    skip: skip,
                    sort: { 'commentedAt': -1 }
                },
                populate: {
                    path: 'commented_by',
                    select: 'personal_info.username personal_info.fullname personal_info.profile_img'
                },
                select: "-blog_id -updatedAt"
            })
            .select("children");

        if (!doc) {
            return res.status(404).json({ error: "Comment not found" });
        }

        return res.status(200).json({ replies: doc.children });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

const deleteComments = async (_id) => {
    try {
        const comment = await Comment.findOneAndDelete({ _id });

        if (!comment) {
            console.log("Comment not found.");
            return;
        }


        if (comment.parent) {
            await Comment.findOneAndUpdate(
                { _id: comment.parent },
                { $pull: { children: _id } }
            );
            console.log('Removed comment from parent');
        }


        await Notification.findOneAndDelete({ comment: _id });
        await Notification.findOneAndUpdate({ reply: _id }, {$unset: {reply: 1}});

        const blogUpdate = {
            $pull: { comments: _id },
            $inc: {
                "activity.total_comments": -1,
                "activity.total_parent-comments": comment.parent ? 0 : -1
            }
        };

        await Blog.findOneAndUpdate({ _id: comment.blog_id }, blogUpdate);

        // Recursively delete replies
        if (comment.children && comment.children.length > 0) {
            for (let replyId of comment.children) {
                await deleteComments(replyId);
            }
        }

    } catch (err) {
        console.error("Error in deleteComments:", err);
    }
};

server.post('/delete-comments', verifyJWT, (req, res) => {
    let user_id = req.user;
    let { _id } = req.body;

    console.log("User ID from token:", user_id);

    Comment.findOne({ _id })
        .then(comment => {

            if (
                user_id === comment.commented_by?.toString() ||
                user_id === comment.blog_author?.toString()
            ) {
                deleteComments(_id);
                return res.status(200).json({ status: 'done' });
            } else {
                return res.status(403).json({ error: 'You are not authorized to delete this comment' });
            }
        })
        .catch(err => {
            console.error("Error in /delete-comments:", err);
            res.status(500).json({ error: "Internal Server Error" });
        });
});

server.post("/change-password", verifyJWT, (req, res) => {
    let {currentPassword, newPassword} = req.body;
    if (!passwordRegex.test(currentPassword) || !passwordRegex.test(newPassword)) {
        return res.status(403).json({error: 'Password must be 6-20 characters and include uppercase, lowercase, and number'})
    }
    User.findOne({_id: req.user})
    .then((user) => {
        if (user.google_auth) {
            return res.status(403).json({error: "You can't change account password because you logged in through google"});
        }

        bcrypt.compare(currentPassword, user.personal_info.password,(err, result) => {
            if (err) {
                return res.status(500).json({error: "Some error occured while changing the password please try again later"});
            }
            if (!result) {
                return res.status(500).json({error: "Incorrect current password"});
            }
            bcrypt.hash(newPassword, 10, (err, hashed_password) => {
                User.findOneAndUpdate({_id: req.user}, {"personal_info.password": hashed_password})
                .then((u) => {
                    return res.status(200).json({status: 'Password change'})
                })
                .catch(err => {
                    return res.status(500).json({err: "Some error occured while changing the password please try again later"});
                })
            })
        })
    })
    .catch(err => {
        console.log(err);
        return res.status(500).json({err: "User not found"})
    })
});

server.post('/upload-profile-image',verifyJWT, uploadProfileImg.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  try {
    return res.status(200).json({ url: req.file.path }); 
  } catch (err) {
    return res.status(500).json({ error: 'Upload failed' });
  }
});

server.post('/update-profile-img', verifyJWT, async (req, res) => {
  const { url } = req.body;

  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.user,
      { "personal_info.profile_img": url },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ profile_img: updatedUser.personal_info.profile_img });
  } catch (err) {
    console.error('Update error:', err);
    return res.status(500).json({ error: 'Something went wrong' });
  }
});

server.post('/update-profile', verifyJWT, (req, res) => {
    let {username, bio, social_links} = req.body;
    let bioLimit = 50;
    if (username.length < 3) {
        return res.status(403).json({error: "Username should be atleast 3 characters long"})
    }
    if (bio.length > bioLimit) {
        return res.status(403).json({error: `Bio should not be more than ${bioLimit}`})
    }
    let socialLinksArr = Object.keys(social_links);
    try {
        for (let i = 0; i < socialLinksArr.length; i++) {
            if (social_links[socialLinksArr[i]].length) {
                let hostname = new URL(social_links[socialLinksArr[i]]).hostname;
                if (!hostname.includes(`${socialLinksArr[i]}.com`) && socialLinksArr[i] !== 'website')  {
                    return res.status(403).json({error: `${socialLinksArr[i]} link is invalid. You must enter a fullname`})
                }
            }
            
        }
    } catch (err) {
        return res.status(403).json({error: "you must provide social links with http(s) inluded"})
    }
    let updateObj = {
        "personal_info.username": username,
        "personal_info.bio": bio,
        social_links
    }
    User.findOneAndUpdate({_id: req.user}, updateObj, {
        runValidators: true
    })
    .then(() => {
        return res.status(200).json({username})
    })
    .catch(err => {
        if (err.code === 11000) {
            return res.status(409).json("User is already taken")
        }
        return res.status(500).json({error: err.message})
    })

});

server.get('/new-notification', verifyJWT, (req, res) => {
    let user_id = req.user;
    Notification.exists({notification_for: user_id, seen: false, user: {$ne: user_id}})
    .then(result => {
        if (result) {
            return res.status(200).json({new_notification_available: true})
        } else {
            return res.status(200).json({new_notification_available: false})
        }
    })
    .catch(err => {
        console.log(err.message)
        return res.status(200).json({error: err.message})
    })
});

server.post('/notifications',verifyJWT, (req, res) => {
    let user_id = req.user;
    let {page, filter, deletedDocCount} = req.body;
    let maxLimit = 10;
    let findQuery = {notification_for: user_id, user: {$ne: user_id}};
    let skipDocs = (page - 1) * maxLimit;
    if (filter !== 'all') {
        findQuery.type = filter;
    }
    if (deletedDocCount) {
        skipDocs -= deletedDocCount;
    }
    Notification.find(findQuery)
    .skip(skipDocs)
    .limit(maxLimit)
    .populate("blog", "title blog_id")
    .populate("user", "personal_info.fullname personal_info.username personal_info.profile_img")
    .populate("comment", "comment")
    .populate("replied_on_comment", "comment")
    .populate("reply", "comment")
    .sort({createdAt: - 1})
    .select("createdAt type seen reply")
    .then(notifications => {
        Notification.updateMany(findQuery, {seen: true})
        .skip(skipDocs)
        .limit(maxLimit)
        .then(() => {
            console.log('Notification seen')
        })
        return res.status(200).json({notifications})
    })
    .catch(err => {
        console.log(err)
        return res.status(500).json({error: err.message})
    })
});

server.post('/all-notifications-count', verifyJWT, (req, res) => {
    let user_id = req.user;
    let {filter} = req.body;
    let findQuery = {notification_for: user_id, user: {$ne: user_id}}
    if (filter !== 'all') {
        findQuery.type = filter;
    }
    Notification.countDocuments(findQuery)
    .then(count => {
        return res.status(200).json({totalDocs: count})
    })
    .catch(err => {
        return res.status(500).json({error: err.message})
    })
});

server.post('/user-written-blogs', verifyJWT, (req, res) => {
    let user_id = req.user;
    let {page, draft, query, deletedDocCount} = req.body;
    let maxLimit = 5;
    let skipDocs = (page - 1) * maxLimit;

    if (deletedDocCount) {
        skipDocs -= deletedDocCount
    }

    Blog.find({author: user_id, draft, title: new RegExp(query, 'i')})
    .skip(skipDocs)
    .limit(maxLimit)
    .sort({publishedAt: -1})
    .select(" title banner publishedAt blog_id activity des draft -_id ")
    .then(blogs => {
        return res.status(200).json({blogs})
    })
    .catch(err => {
        return res.status(500).json({error: err.message})
    })

});
server.post('/user-written-blogs-count' , verifyJWT, (req, res) => {
    let user_id = req.user;
    let {draft, query} = req.body;

    Blog.countDocuments({author: user_id, draft, title: new RegExp(query, 'i')})
    .then(count => {
        return res.status(200).json({totalDocs: count})
    })
    .catch(err => {
        console.log(err.message)
        return res.status(500).json({error: err.message})
    })
});

server.post('/delete-blog' , verifyJWT, (req, res) => {
    let user_id = req.user;
    let {blog_id} = req.body;
    Blog.findOneAndDelete({blog_id})
    .then(blog => {
        Notification.deleteMany({blog: blog._id}).then(data => console.log('notifications deleted'));
        Comment.deleteMany({blog_id: blog._id}).then(data => console.log('comments deleted'));
        User.findOneAndUpdate({_id: user_id}, {$pull: {blog: blog._id}, $inc: {"account_info.total_post": -1}})
        .then(user => console.log("Blog deleted"))
        return res.status(200).json({status: 'done'});
    })
    .catch(err => {
        return res.status(500).json({error: err.message})
    })

});

server.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);
});