import mongoose from "mongoose";

const getRandomGameryAvatar = () => {
    // A list of cool, gamery avatar styles from DiceBear
    const avatarStyles = [
        'pixel-art-neutral',
        'adventurer',
        'bottts'
    ];

    // 1. Randomly select one of the styles from the list
    const style = avatarStyles[Math.floor(Math.random() * avatarStyles.length)];
    
    // 2. Generate a random string (seed) to make each avatar unique
    const seed = Math.random().toString(36).substring(2, 12);

    // 3. Construct and return the final URL
    return `https://api.dicebear.com/8.x/${style}/svg?seed=${seed}`;
};

export const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true
    },
    RecoveryEmail:{
        type: String,
        required: false,
    },
    RecoveryPassword:{
        type: String,
        required: false,
    },    
    avatar: {
        type: String,
        default: getRandomGameryAvatar()
    },
        likedGames: {
        type: [String], 
        default: []
    },
    ratedGames: {
        type: Map,
        of: Number,
        default: {}
    }
})