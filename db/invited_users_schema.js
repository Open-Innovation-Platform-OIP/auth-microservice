const {
    promisify
} = require('util');
const Knex = require('knex');
const connection = require('../knexfile');
const {
    Model
} = require('objection');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const knexConnection = Knex(connection);
const randomBytesAsync = promisify(crypto.randomBytes);

Model.knex(knexConnection);

class InvitedUsers extends Model {
    static get tableName() {
        return 'invited_users'
    }

    static get idColumn() {
        return 'id';
    }

    getInvitedUser() {
        return {
            'id': this.id,
            'email': this.email,
            'accepted': this.accepted,

        }
    }

    async $beforeInsert() {
        const salt = bcrypt.genSaltSync();
        this.password = await bcrypt.hash(this.password, salt)
        const createRandomToken = await randomBytesAsync(16).then(buf => buf.toString('hex'));
        this.token = createRandomToken
    }

    // verifyPassword(password, callback) {
    //     bcrypt.compare(password, this.password, callback)
    // };

    // static get jsonSchema() {
    //     return {
    //         type: 'object',
    //         required: ['email'],
    //         properties: {
    //             id: {
    //                 type: 'integer'
    //             },
    //             email: {
    //                 type: 'string',
    //                 minLength: 1,
    //                 maxLength: 255
    //             },
    //         }
    //     }
    // }
}

module.exports = {
    InvitedUsers
}