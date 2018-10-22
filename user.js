/*
 * @category   Security Agencies
 * @package    security.multipapp.com
 * @author     Nichi-in <author@nichi.com>
 * @copyright  2017-2018 MultiApps
 * @license    ""
 * @version    1.0
 * @link       http://www.multiappstechnologies.com
 */
const User = require('../models/user');
const Agency = require('../models/agency');
const Client = require('../models/client');
const Attendance = require('../models/attendance');
const Patrolling = require('../models/patrolling');
const UserSites = require('../models/user_site');
const SiteUser = require('../models/site_user');
const PatrollingList = require('../models/patrolling_list');
const UserCurrentLocation = require('../models/user_current_location');
const DutyChart = require('../models/duty_chart');
const UserOtp = require('../models/user_otp');
const config = require('../config');
const Common = require('../helper/common');
const bcrypt = require('bcrypt');
const responseStatus = require('../helper/status');
const jwt = require('jwt-simple');
var ObjectId = require('mongoose').Types.ObjectId;
const Config = require('../config');
const Duty = require('../models/duty');
const Async = require('async');
const UserPatrolling = require('../models/user_patrolling');
/* Accepts platform user details and does login. returns success or validation messages
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.logIn = function (req, res, next) {
    if (!req.body.mobile || !req.body.password) {
        return res.status(200).send({
            status: responseStatus.fieldsRequired.code
        });
    } else {
        /* Check for passport authenticated user */
        if (req.user === responseStatus.objectNotFound.code) {
            return res.status(200).send({
                status: responseStatus.accountNotFound.code
            });
        }
        if (req.user === responseStatus.accountNotActivated.code) {
            return res.status(200).send({
                status: responseStatus.accountNotActivated.code
            });
        }
        /* Check for password match */
        bcrypt.compare(req.body.password, req.user.password, function (err, result) {

            if (!result) {
                return res.status(200).send({
                    status: responseStatus.invalidCredentials.code
                });
            }
            console.log(' Login processing....'+req.user);
            var userDetail = {};
            userDetail['userid'] = req.user.userid;
            userDetail['_id'] = req.user._id;
            userDetail['username'] = req.user.first_name + " " + req.user.last_name;
            userDetail['avatar'] = req.user.avatar;
            userDetail['usercontactinfo'] = req.user.usercontactinfo;
            userDetail['address'] = req.user.address;
            userDetail['agency'] = req.user.agency;
            userDetail['role'] = req.user.role;
            userDetail['reporting_to'] = req.user.reporting_to;

            //update Device ID
            User.findByIdAndUpdate(req.user._id, {
                $set: {
                    "deviceId": req.body.deviceId
                }
            }, function (err, userObject) {
                if (err) {
                    console.log(err);
                }
                console.log(userObject);
                
            });

            return res.send({
                status: responseStatus.loginSuccess.code,
                token: Common.tokenForUser(req.user),
                user: userDetail
            });
        });
    }
}

/* Accepts platform user details and does signup. returns success or validation messages
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.signUp = function (req, res, next) {
    try {
        if (!req.body.email || !req.body.password || !req.body.first_name || !req.body.last_name || !req.body.mobile || !req.body.agency || !req.body.role || !req.body.date_of_joining) {
            return res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        }
        checkAgencyPackageLimit(req.body.agency, function (responseObject) {
            if (responseObject.status === responseStatus.successResponse.code) {
                /* See if the user with given email address already exists */
                var query={
                    $and : [
                        { $or : [  { email: req.body.email }, { 'contact_info.mobile': req.body.mobile } ] },
                        {status:new ObjectId(Config.activeStatusId)}
                    ]
                } ;
                User.findOne(query, function (err, userObject) {
                    if (err) {
                        return res.status(200).send({
                            status: responseStatus.queryError.code,
                            description: err
                        });
                    }
                    /* If a user with email does exist return an error */
                    if (userObject) {
                        if (userObject.email === req.body.email) {
                            return res.status(200).send({
                                status: responseStatus.emailExist.code
                            });
                        }
                        if (userObject.contact_info.mobile === req.body.mobile) {
                            return res.status(200).send({
                                status: responseStatus.phoneExist.code
                            });
                        }
                    }
                    /* If a user email does not exist, save and create and save user record */
                    Common.readStatusId(Config.activeStatus, function (statusId) {
                        req['body']['status'] = statusId;
                        req['body']['contact_info'] = { 'mobile': req.body.mobile, 'alternative_no': req.body.alternative_no };
                        req['body']['current_address'] = { 'zipcode': req.body.currentAddressZipCode, 'address2': req.body.currentAddress2, 'address1': req.body.currentAddress1 };
                        req['body']['permanent_address'] = { 'zipcode': req.body.permanentAddressZipCode, 'address2': req.body.permanentAddress2, 'address1': req.body.permanentAddress1 };
                        req['body']['avatar'] = req.body.storage;
                        const user = User.constructUser(req);
                        /* Don't assign current location */
                        saveUserCurrentLocationIfNotExist("", "", user._id, function (response) {
                            if (response.status === responseStatus.successResponse.code) {
                                Common.encrypt(user.pin, function (hash) {
                                    user.pin = hash;
                                    user.current_location = response.data._id;
                                    user.save(function (saveError) {
                                        if (saveError) {
                                            return res.status(200).send({
                                                status: responseStatus.queryError.code,
                                                description: saveError
                                            });
                                        }
                                        return res.status(200).send({
                                            status: responseStatus.activate.code
                                        });
                                    });
                                });
                            } else {
                                return res.status(200).send({
                                    status: responseStatus.queryError.code
                                });
                            }
                        });
                    });
                });
            } else {
                return res.status(200).send(responseObject);
            }
        });
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
        });
    }
}


function saveUserCurrentLocationIfNotExist(lat, lon, userId, callback) {
    Common.readStatusId(Config.activeStatus, function (statusId) {
        const statusObject = UserCurrentLocation.constructUserCurrentLocation(userId, lat, lon, statusId);
        /* save UserCurrentLocation object */
        statusObject.save(function (err, savedUserCurrentLocationObject) {
            /* On  Save Error*/
            if (err) {
                callback({ status: responseStatus.queryError.code });
            }
            callback({ status: responseStatus.successResponse.code, data: statusObject });
        });
    });
}


/* csv file upload*/
/* Accepts platform user details and does multiple signup. returns success or validation messages
* @param JSON req - post data
* @param JSON res - sending the resulted data
* @param JSON next - callback for specific error handling
* @returns response
*/
exports.csvSignUp = function (req, res, next) {
    try {
        if (!req.body.email || !req.body.password || !req.body.first_name || !req.body.last_name || !req.body.mobile || !req.body.agency || !req.body.role || !req.body.date_of_joining) {
            return res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        }

        //get reporting to based on mobile and agency
    readReportingToSupervisor(req, function (responseSupervisorObject) {  
       // console.log("response object"+JSON.stringify(responseSupervisorObject));
        if (responseSupervisorObject.status === responseStatus.successResponse.code) {
            if(responseSupervisorObject.data){
                req['body']['reporting_to']=responseSupervisorObject.data._id;
            }else{
                return res.status(200).send({
                    status: responseStatus.accountNotFound.code
                });
            }
        }else{
            return res.status(200).send(responseSupervisorObject);
        }

        checkAgencyPackageLimit(req.body.agency, function (responseObject) {
            if (responseObject.status === responseStatus.successResponse.code) {
                /* See if the user with given email address already exists */
                var query={
                    $and : [
                        { $or : [  { email: req.body.email }, { 'contact_info.mobile': req.body.mobile } ] },
                        {status:new ObjectId(Config.activeStatusId)}
                    ]
                } ;
                User.findOne(query, function (err, userObject) {
                    if (err) {
                        return res.status(200).send({
                            status: responseStatus.queryError.code,
                            description: err
                        });
                    }
                    /* If a user with email does exist return an error */
                    if (userObject) {
                        if (userObject.email === req.body.email) {
                            return res.status(200).send({
                                status: responseStatus.emailExist.code
                            });
                        }
                        if (userObject.contact_info.mobile === req.body.mobile) {
                            return res.status(200).send({
                                status: responseStatus.phoneExist.code
                            });
                        }
                    }
                    /* If a user email does not exist, save and create and save user record */
                    Common.readStatusId(Config.activeStatus, function (statusId) {
                        req['body']['status'] = statusId;
                        req['body']['contact_info'] = { 'mobile': req.body.mobile, 'alternative_no': req.body.alternative_no };
                        req['body']['current_address'] = { 'zipcode': req.body.currentAddressZipCode, 'address2': req.body.currentAddress2, 'address1': req.body.currentAddress1 };
                        req['body']['permanent_address'] = { 'zipcode': req.body.permanentAddressZipCode, 'address2': req.body.permanentAddress2, 'address1': req.body.permanentAddress1 };
                        req['body']['avatar'] = req.body.storage;
                        const user = User.constructUser(req);
                        /* Don't assign current location */
                        saveUserCurrentLocationIfNotExist("", "", user._id, function (response) {
                            if (response.status === responseStatus.successResponse.code) {
                                Common.encrypt(user.pin, function (hash) {
                                    user.pin = hash;
                                    user.current_location = response.data._id;
                                    user.save(function (saveError) {
                                        if (saveError) {
                                            return res.status(200).send({
                                                status: responseStatus.queryError.code,
                                                description: saveError
                                            });
                                        }
                                        return res.status(200).send({
                                            status: responseStatus.activate.code
                                        });
                                    });
                                });
                            } else {
                                return res.status(200).send({
                                    status: responseStatus.queryError.code
                                });
                            }
                        });
                    });
                });
            } else {
                return res.status(200).send(responseObject);
            }
        });

    });
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
        });
    }
}

function readReportingToSupervisor(req, callback) {
  //  console.log("reporting to "+req.body.agency+" mobile"+req.body.mobile);
  var query;
  if(req.body.role.toString()===Config.roleSupervisorId.toString()){
  //  console.log("supervisor");
    query={agency: new ObjectId(req.body.agency), 'role': {$in: [Config.roleAgencyId]}, status: new ObjectId(Config.activeStatusId)};
  }else{
     // console.log("guard");
    query={'contact_info.mobile': req.body.reporting_to,agency:new ObjectId(req.body.agency), status: new ObjectId(Config.activeStatusId) };
  } 
    User.findOne(query, function (err, supervisordata) {
        if (err) {
            return callback({ status: responseStatus.queryError.code });
        }
      //  console.log("response data"+JSON.stringify(supervisordata));
        return callback({ data: supervisordata, status: responseStatus.successResponse.code });
    }).select('first_name last_name role');
}
/* CSV file Upload*/

/* Accepts platform user details and does account activation. returns success or validation messages
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.activate = function (req, res, next) {
    if (!req.params.token) {
        return res.status(200).send({
            error: responseStatus.enterActivationCode.code
        });
    }
    const userId = jwt.decode(req.params.token, config.secret).sub;
    try {
        User.findByIdAndUpdate(userId, {
            $set: {
                "status": responseStatus.active.string
            }
        }, function (err, userObject) {
            if (err) {
                return res.status(200).send({
                    status: responseStatus.queryError.code,
                    description: err
                });
            }
            if (userObject) {
                return res.sendFile(path.join(__dirname, '../public', 'index.html'));
            } else {
                return res.status(200).send({
                    status: responseStatus.accountNotFound.code
                });
            }
        });
    } catch (e) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code,
            description: e
        });
    }
}

/* Accepts platform user details and does account activation. returns success or validation messages
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.isPhoneExist = function (req, res, next) {
    if (!req.body.mobile) {
        return res.status(200).send({
            error: responseStatus.enterActivationCode.code
        });
    }
    checkPhoneExist(req.body.mobile, function (responseObject) {
        return res.status(200).send(responseObject);
    });
}

/* Accepts userid and Token to update
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.updateDeviceToken = function (req, res, next) {
    if (!req.body.token || !req.body.userId) {
        return res.status(200).send({
            error: responseStatus.fieldsRequired.code
        });
    } else {
        User.findByIdAndUpdate(req.body.userId, {
            $set: {
                "deviceId": req.body.token
            }
        }, function (updatedObjectErr, updatedObject) {
            if (updatedObjectErr) {
                return res.status(200).send({
                    status: responseStatus.queryError.code
                });
            }
            return res.status(200).send({
                status: responseStatus.successResponse.code
            });
        });
    }
}

/* Check Phone Exist or Not*/
function checkPhoneExist(mobile, callback) {
    try {
        User.findOne({ 'contact_info.mobile': mobile }, function (err, userObject) {
            /* On  Update Error*/
            if (err) {
                return callback({
                    status: responseStatus.queryError.code
                });
            }
            if (!userObject) {
                return callback({
                    status: responseStatus.phoneAvailable.code
                });
            }
            return callback({
                status: responseStatus.phoneExist.code
            });
        });
    } catch (e) {
        return callback({ status: responseStatus.exceptionError.code });
    }
}

/* Accepts platform user email and return email. returns success or validation messages
 * @param JSON req - post data
 * @param JSON res - sending the resulted data through email
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.forgotPassword = function (req, res, next) {
    if (!req.body.mobile) {
        return res.status(200).send({
            status: responseStatus.fieldsRequired.code
        });
    }
    User.findOne({
        'contact_info.mobile': req.body.mobile
    }, function (err, userObject) {
        if (err) {
            return res.status(200).send({
                status: responseStatus.queryError.code,
                description: err
            });
        }
        /*check whether the user account is active or not*/
        if (userObject) {
            if (userObject.status == Config.inActiveStatusId) {
                return res.status(200).send({
                    status: responseStatus.accountNotActivated.code
                });
            }
        }
        /* If a user does exist return an error */
        if (userObject) {
            var userOtp = UserOtp.constructOTP(userObject._id, Math.floor(10000 + Math.random() * 90000));
            Common.sendSMS('91' + req.body.mobile, userOtp.otp + ' is your OTP for changing password.');
            var savedUserOtp = userOtp.save();
            savedUserOtp.catch(function (err) {
                console.log(err);
            })
            savedUserOtp.then(function (user_otp) {
                /* SMS Gateway call to send OTP */
                return res.status(200).send({
                    status: responseStatus.otpSent.code,
                    userId: userObject._id
                });
            });
        } else {
            return res.status(200).send({
                status: responseStatus.accountNotFound.code
            });
        }
    });
}

/* Accepts platform user mobile and return otp. returns success or validation messages
 * @param JSON req - post data
 * @param JSON res - sending the resulted data through email
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.forgotPin = function (req, res, next) {
    if (!req.body.mobile || !req.body.userId) {
        return res.status(200).send({
            status: responseStatus.fieldsRequired.code
        });
    }
    User.findById(req.body.userId, function (err, userObject) {
        if (err) {
            return res.status(200).send({
                status: responseStatus.queryError.code,
                description: err
            });
        }
        /*check whther user is active or not*/
        if (userObject) {
            if (userObject.status == Config.inActiveStatusId) {
                return res.status(200).send({
                    status: responseStatus.accountNotActivated.code
                });
            }
        }
        /* Compare mobile number with DB mobile number */
        if (userObject.contact_info.mobile !== req.body.mobile) {
            return res.status(200).send({
                status: responseStatus.invalidPhoneNumber.code,
            });
        }
        /* If a user does exist return an error */
        if (userObject) {
            var newPin = Math.floor(1000 + Math.random() * 9000) + "";
            //var userOtp = UserOtp.constructOTP(userObject._id, 12345);
            Common.sendSMS('91' + req.body.mobile, newPin + ' is your new pin to login.');
            /* Since we can't decrypt pin, we are generating one random pin and sending via sms */
            Common.encrypt(newPin, function (hash) {
                /* Update new Pin in DB */
                User.findByIdAndUpdate(req.body.userId, {
                    $set: {
                        "pin": hash
                    }
                }, function (updatedObjectErr, updatedObject) {
                    if (updatedObjectErr) {
                        return res.status(200).send({
                            status: responseStatus.queryError.code
                        });
                    }
                    return res.status(200).send({
                        status: responseStatus.otpSent.code,
                        userId: userObject._id
                    });
                });
            });
        } else {
            return res.status(200).send({
                status: responseStatus.accountNotFound.code
            });
        }
    });
}

/* Accepts OTP . return reset pin
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.validateResetPinOTP = function (req, res, next) {
    if (!req.body.otp || !req.body.userId) {
        return res.status(200).send({
            status: responseStatus.fieldsRequired.code
        });
    }
    UserOtp.findOne({
        user: new ObjectId(req.body.userId),
        otp: req.body.otp,
        status: "ACTIVE"
    }, function (err, otpObject) {
        if (err) {
            return res.status(200).send({
                status: responseStatus.queryError.code,
                description: err
            });
        }
        /* If a user with email does exist return an error */
        if (otpObject) {
            otpObject.status = "INACTIVE";
            otpObject.save(function (saveError) {
                if (saveError) {
                    return res.status(200).send({
                        status: responseStatus.queryError.code
                    });
                }
                /* Set some random pin and send to user */
                Common.encrypt(1234 + "", function (hash) {
                    User.findByIdAndUpdate(req.body.userId, {
                        $set: {
                            "pin": hash
                        }
                    }, function (userObjectErr, userObject) {
                        if (userObjectErr)
                            return res.status(200).send({
                                status: responseStatus.queryError.code,
                                description: userObjectErr
                            });
                        Common.sendSMS('91' + otpObject.user.mobile, 1234 + ' is your new Pin.');
                        return res.status(200).send({
                            status: responseStatus.successResponse.code
                        });
                    });
                });
            });
        } else {
            return res.status(200).send({
                status: responseStatus.invalidOTP.code
            });
        }
    }).populate([{
        path: 'user',
        select: 'contact_info.mobile'
    }]);
}

/* Accepts Device Token . return reset password html 
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.validateResetPasswordOTP = function (req, res, next) {
    if (!req.body.otp || !req.body.userId) {
        return res.status(200).send({
            status: responseStatus.fieldsRequired.code
        });
    }
    UserOtp.findOne({
        user: new ObjectId(req.body.userId),
        otp: req.body.otp,
        status: "ACTIVE"
    }, function (err, otpObject) {
        if (err) {
            return res.status(200).send({
                status: responseStatus.queryError.code,
                description: err
            });
        }
        /* If a user with email does exist return an error */
        if (otpObject) {
            otpObject.status = "INACTIVE";
            otpObject.save(function (saveError) {
                if (saveError) {
                    return res.status(200).send({
                        status: responseStatus.queryError.code
                    });
                }
                return res.status(200).send({
                    status: responseStatus.successResponse.code
                });
            });
        } else {
            return res.status(200).send({
                status: responseStatus.invalidOTP.code
            });
        }
    });
}

/* Accepts User id and Password . return reset password html 
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.resetPassword = function (req, res, next) {
    if (!req.body.password && !req.body.userId) {
        return res.status(200).send({
            status: responseStatus.fieldsRequired.code
        });
    }
    Common.encrypt(req.body.password, function (hash) {
        User.findByIdAndUpdate(req.body.userId, {
            $set: {
                "password": hash
            }
        }, function (userObjectErr, userObject) {
            if (userObjectErr)
                return res.status(200).send({
                    status: responseStatus.queryError.code,
                    description: userObjectErr
                });
            req.logout();
            return res.status(200).send({
                status: responseStatus.successResponse.code
            });
        });
    });
}

/* Accepts User Id and Pin . return reset pin  
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.resetPin = function (req, res, next) {
    if (!req.body.oldPin || !req.body.newPin || !req.body.userId) {
        return res.status(200).send({
            status: responseStatus.fieldsRequired.code
        });
    }
    /* Read User */
    User.findById(req.body.userId, function (userObjectErr, userObject) {
        if (userObjectErr) {
            return res.status(200).send({
                status: responseStatus.queryError.code,
                description: userObjectErr
            });
        }
        /* Match with Old Pin */
        bcrypt.compare(req.body.oldPin, userObject.pin, function (err, result) {
            if (err) {
                return res.status(200).send({
                    status: responseStatus.queryError.code,
                    description: userObjectErr
                });
            }
            /* Pin Match Success */
            if (result) {
                Common.encrypt(req.body.newPin, function (hash) {
                    /* Update new Pin in DB */
                    User.findByIdAndUpdate(req.body.userId, {
                        $set: {
                            "pin": hash
                        }
                    }, function (updatedObjectErr, updatedObject) {
                        if (updatedObjectErr) {
                            return res.status(200).send({
                                status: responseStatus.queryError.code,
                                description: userObjectErr
                            });
                        }
                        return res.status(200).send({
                            status: responseStatus.successResponse.code
                        });
                    });
                });
            } else {
                return res.status(200).send({ status: responseStatus.invalidPin.code });
            }
        });
    });
}


/**
 * User update avatar
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.changeAvatar = function (req, res, next) {
    try {
        if (!req.body.user || !req.body.destination) {
            return res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        } else {
            User.findByIdAndUpdate(req.body.user, {
                $set: {
                    "avatar": req.body.storage
                }
            }, function (userObjectErr, userObject) {
                if (userObjectErr) {
                    return res.status(200).send({
                        status: responseStatus.queryError.code
                    });
                }
                if (!userObject) {
                    return res.status(200).send({
                        status: responseStatus.userAvatarUpdateFailed.code
                    });
                }
                return res.status(200).send({
                    status: responseStatus.successResponse.code,
                    avatar: req.body.storage
                });
            });
        }
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
        });
    }
}


/**
 * User pagination with name filter
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.readmore = function (req, res, next) {
    try {
        if (!req.body.start || !req.body.limit) {
            res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        } else {
            User.find({ name: new RegExp(req.body.search, 'i') }, function (err, data) {
                if (err)
                    return res.status(200).send({ status: responseStatus.queryError.code });
                return res.status(200).send({ data: data, status: responseStatus.successResponse.code });
            }).select('-password -pin').skip(req.body.start).limit(Number(req.body.limit)).sort({ name: 1 });
        }
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
            , description: exception
        });
    }
}

/**
 * User Read By Id 
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.readProfile = function (req, res, next) {
    try {
        if (!req.body.id) {
            res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        } else {
            User.findById(req.body.id, function (err, data) {
                if (err)
                    return res.status(200).send({ status: responseStatus.queryError.code });
                return res.status(200).send({ data: data, status: responseStatus.successResponse.code });
            }).select('contact_info.mobile role dob bloodGroup avatar first_name last_name userid agency permanent_address current_address reporting_to').populate([{
                path: 'reporting_to',
                select: 'first_name last_name contact_info.mobile'
            }, {
                path: 'agency',
                select: 'name'
            },
            {
                path: 'role',
                select: 'name'
            }]);
        }
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
            , description: exception
        });
    }
}

/* Accepts User id and Password . return reset password html 
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.changePhoneNumber = function (req, res, next) {
    if (!req.body.otp || !req.body.oldPhone || !req.body.newPhone || !req.body.userId) {
        return res.status(200).send({
            status: responseStatus.fieldsRequired.code
        });
    }
    User.findById({ '_id': req.body.userId, 'contact_info.mobile': req.body.oldPhone }, {
        $set: {
            "contact_info.mobile": req.body.newPhone
        }
    }, function (userObjectErr, userObject) {
        if (userObjectErr)
            return res.status(200).send({
                status: responseStatus.queryError.code,
                description: userObjectErr
            });
        if (!userObject) {
            return res.status(200).send({
                status: responseStatus.accountNotFound.code
            });
        } else {
            return res.status(200).send({
                status: responseStatus.successResponse.code
            });
        }
    });
}

/* Accepts User id and Password . return reset password html 
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.userList = function (req, res, next) {
    var dtDraw = req.body.draw;
    var start = req.body.start;
    var length = req.body.length;
    var search = req.body.search.value;
    var orderFieldIndex = req.body.order[0].column;
    var orderField = req.body.columns[orderFieldIndex].data;
    var orderType = req.body.columns[orderFieldIndex].dir;
    if (req.body.order[0].dir === 'desc') {
        orderBy = 'descending';
    } else {
        orderBy = 'ascending';
    }
    try {
        var query = { role: new ObjectId(req.body.role), $or: [{ first_name: new RegExp(search, 'i') }, { 'last_name': new RegExp(search, 'i') }, { 'email': new RegExp(search, 'i') }, { 'contact_info.mobile': new RegExp(search, 'i') }] };
        if (req.body.agency) {
            query['agency'] = new ObjectId(req.body.agency);
        }
        User.find(query, function (err, existingUsers) {
            if (err) {
                console.log(err)
                return res.status(200).send({ error: "Invalid API" });
            }
            if (existingUsers) {
                User.count(query, function (err, count) {
                    if (err) {
                        return res.status(200).send({ error: "Not found" })
                    }
                    if (search !== "") {
                        var filteredUsers = existingUsers;
                        filteredUsers = filteredUsers.filter(function (obj) {
                            var patternsearch = new RegExp("^.*" + search + ".*", "gi");
                            try {
                                return obj.agency.name.match(patternsearch) || obj.status.name.match(patternsearch) || obj.reporting_to.first_name.match(patternsearch) || obj.reporting_to.last_name.match(patternsearch) || obj.role.name.match(patternsearch) || obj.first_name.match(patternsearch) || obj.last_name.match(patternsearch) || obj.email.match(patternsearch) || obj.contact_info.mobile.match(patternsearch);
                            } catch (e) {
                                console.log(e);
                            }
                        });
                        return res.status(200).send({
                            draw: dtDraw,
                            recordsTotal: filteredUsers.length,
                            recordsFiltered: filteredUsers.length,
                            data: filteredUsers
                        });
                    }
                    return res.status(200).send({
                        draw: dtDraw,
                        recordsTotal: count,
                        recordsFiltered: count,
                        data: existingUsers
                    });

                });
            } else {
                return res.status(200).send({ error: "Not found" });
            }
        }).select('first_name last_name email reporting_to agency role status date_of_joining contact_info.mobile avatar').skip(Number(start)).limit(Number(length)).sort([[orderField, orderBy]]).populate([{
            path: 'reporting_to',
            select: 'first_name last_name'
        }, {
            path: 'agency',
            select: 'name status'
        },
        {
            path: 'status',
            select: 'name'
        },
        {
            path: 'role',
            select: 'name'
        }]);
    } catch (e) {
        console.log(e);
    }
}

/**
 * Read Supervisor Guards location
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.readSuperVisorGuardsPatrolling = function (req, res, next) {
    try {
        if (!req.body.site || !req.body.supervisorId || !req.body.date || !req.body.start_time || !req.body.patrollingId) {
            return res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        } else {
            var patrolObj = {
                patrolling: function (callback) {
                    var timeObject = Common.getStartAndEndTime(req.body.date);
                    /* Read Supervisor Guards */
                    if (req.body.client) {
                        PatrollingList.find({ patrolling: new ObjectId(req.body.patrollingId), site: new ObjectId(req.body.site), created_at: { "$gte": timeObject.dayStartTime / 1000, "$lte": timeObject.dayEndTime / 1000 } }, function (patrolErr, patrollingList) {
                            if (patrolErr) {
                                return callback(patrolErr);
                            }
                            callback(null, patrollingList);
                            /* Populated Filter */
                        }).select('route user patrolling_completed').populate([{
                            path: 'user',
                            select: 'first_name last_name userid avatar contact_info.mobile'
                        }]);
                    } else {
                        User.find({ 'reporting_to': new ObjectId(req.body.supervisorId) }, function (err, userObjects) {
                            if (err) {
                                return callback(err);
                            }
                            if (!userObjects) {
                                callback(null, []);
                            }
                            var guardIds = Common.readUserIds(userObjects);
                            PatrollingList.find({ patrolling: new ObjectId(req.body.patrollingId), site: new ObjectId(req.body.site), user: { $in: guardIds }, created_at: { "$gte": timeObject.dayStartTime / 1000, "$lte": timeObject.dayEndTime / 1000 } }, function (patrolErr, patrollingList) {
                                if (patrolErr) {
                                    return callback(err);
                                }
                                callback(null, patrollingList);
                                /* Populated Filter */
                            }).select('route user patrolling_completed').populate([{
                                path: 'user',
                                select: 'first_name last_name userid avatar contact_info.mobile'
                            }]);
                        }).select('_id');
                    }
                },
                predefinedroute: function (callback) {
                    Patrolling.findById(req.body.patrollingId, function (err, patrolling) {
                        if (err) {
                            return callback(err);
                        }
                        callback(null, patrolling);
                    }).select("patrolling_route estimated_time").populate([{
                        path: 'patrolling_route',
                        select: 'patrolling_points'
                    }]);
                }
            };
            Async.parallel(patrolObj, function (err, results) {
                try {
                    if (err) {
                        return res.status(200).send({
                            status: responseStatus.queryError.code
                        });
                    }
                    results['estimated_time'] = results.predefinedroute.estimated_time;
                    results['predefinedroute'] = results.predefinedroute.patrolling_route.patrolling_points;
                    return res.status(200).send({
                        status: responseStatus.successResponse.code,
                        data: results
                    });
                } catch (e) {
                    return res.status(200).send({
                        status: responseStatus.exceptionError.code
                    });
                }
            });
        }
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
        });
    }
}

/**
 * Read Supervisor Sites
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.readUserSites = function (req, res, next) {
    try {
        if (!req.body.userId || !req.body.role) {
            return res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        } else {
            var query, populateObject, selectObject;
            if (req.body.role === Config.client) {
                Client.findOne({ representId: new ObjectId(req.body.userId) }, function (clientErr, clientObject) {
                    if (clientErr) {
                        return res.status(200).send({
                            status: responseStatus.queryError.code
                        });
                    }
                    if (!clientObject) {
                        return res.status(200).send({
                            status: responseStatus.objectNotFound.code
                        });
                    }
                    query = { client: clientObject._id };
                    selectObject = 'site user';
                    populateObject = [{
                        path: 'site',
                        select: 'name address avatar'
                    }, {
                        path: 'user',
                        select: 'first_name last_name contact.mobile'
                    }];
                    readClientSites(clientObject._id, function (response) {
                        return res.status(200).send(response);
                    });
                }).select('_id').lean();
            } else {
                UserSites.findOne({ user: new ObjectId(req.body.userId) }, function (err, siteObjects) {
                    if (err) {
                        return res.status(200).send({
                            status: responseStatus.queryError.code
                        });
                    }
                    if (!siteObjects) {
                        return res.status(200).send({
                            status: responseStatus.objectNotFound.code,
                            description: responseStatus.objectNotFound.description
                        });
                    }
                    countSiteUsers(Common.sortSites(siteObjects.site), req.body.userId, function (response) {
                        siteObjects.site = response;
                        return res.status(200).send({
                            status: responseStatus.successResponse.code,
                            data: siteObjects
                        });
                    });
                }).select('site').sort({ updated_at: -1 }).populate([{
                    path: 'site',
                    select: 'name address avatar client',
                    populate: {
                        path: 'client',
                        model: 'client',
                        select: 'orgName representId',
                        populate: {
                            path: 'representId',
                            model: 'user',
                            select: 'first_name last_name contact_info.mobile'
                        }
                    }
                }]).lean();
            }
        }
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
        });
    }
}

/* Read Client Supervisors*/
function clientSupervisors(sites, callback) {
    /* Read client sites */
    UserSites.find({ 'site': { $in: sites } }, function (userSiteErr, userSiteObjects) {
        if (userSiteErr) {
            return callback({
                status: responseStatus.queryError.code
            });
        }
        if (!userSiteObjects) {
            return callback({
                status: responseStatus.objectNotFound.code
            });
        }
        return callback({ status: responseStatus.successResponse.code, data: userSiteObjects });
    }).select('user site').populate([{
        path: 'site',
        select: '_id'
    }, {
        path: 'user',
        select: 'first_name last_name contact_info.mobile'
    }]).lean();
    ;
}
/* Read Client Sites*/
function readClientSites(clientId, callback) {
    /* Read client sites */
    SiteUser.find({ 'client': clientId }, function (siteErr, siteUserObjects) {
        if (siteErr) {
            return callback({
                status: responseStatus.queryError.code
            });
        }
        if (!siteUserObjects) {
            return callback({
                status: responseStatus.objectNotFound.code
            });
        }
        var siteIds = [];
        siteUserObjects.forEach(function (siteOb) {
            try {
                siteIds.push(siteOb.site._id);
            } catch (e) {
            }
        });
        clientSupervisors(siteIds, function (response) {
            if (responseStatus.successResponse.code === response.status) {
                var result = [];
                siteUserObjects.forEach(function (siteOb) {
                    try {
                        result.push({ '_id': siteOb.site._id, 'avatar': siteOb.site.avatar, 'address': siteOb.site.address, 'name': siteOb.site.name, 'guard_count': siteOb.user.length, 'supervisor': getSiteSupervisorData(response.data, siteOb.site._id) });
                    } catch (e) {
                    }
                });
                return callback({ data: { site: result }, status: responseStatus.successResponse.code });
            } else {
                return callback(siteUserObjects);
            }
        });
    }).select('site user').populate([{
        path: 'site',
        select: 'name address avatar'
    }]).lean();
}

function getSiteSupervisorData(siteUsers, siteId) {
    for (var i = 0; i < siteUsers.length; i++) {
        try {
            for (var j = 0; j < siteUsers[i].site.length; j++) {
                if (siteUsers[i].site[j]._id.toString() === siteId.toString()) {
                    return siteUsers[i].user;
                }
            }
        } catch (e) {
        }
    }
    return {};
}

/* Count Site users*/
function countSiteUsers(siteObjects, userId, callback) {
    /* Read Each site onduty guard count */
    var siteIds = [];
    siteObjects.forEach(function (site, index) {
        siteIds.push(site._id);
    });
    User.find({ 'reporting_to': new ObjectId(userId) }, function (err, userObjects) {
        if (err) {
            return callback(siteObjects);
        }
        if (!userObjects) {
            return callback(siteObjects);
        }
        SiteUser.find({ 'site': { $in: siteIds } }, function (siteErr, siteUserObjects) {
            if (siteErr) {
                return callback(siteObjects);
            }
            if (!siteUserObjects) {
                return callback(siteObjects);
            }
            siteObjects.forEach(function (site, index) {
                site['guard_count'] = countSupervisorSiteUsers(siteUserObjects, userObjects, site._id);
            });
            return callback(siteObjects);
        }).populate([{
            path: 'user',
            select: '_id'
        }]);
    });
}
function countSupervisorSiteUsers(siteUsers, supervisorGuards, siteId) {
    for (var i = 0; i < siteUsers.length; i++) {
        if (siteUsers[i].site.toString() === siteId.toString()) {
            var count = 0;
            for (var j = 0; j < supervisorGuards.length; j++) {
                for (var k = 0; k < siteUsers[i].user.length; k++) {
                    if (siteUsers[i].user[k]._id.toString() === supervisorGuards[j]._id.toString()) {
                        count++;
                    }
                }
            }
            return count;
        }
    }
    return 0;
}

/**
 * Read Guards who is not assigned to any duty
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.readDutyUnassignedGuards = function (req, res, next) {
    try {
        if (!req.body.site || !req.body.supervisorId || !req.body.date || !req.body.duty) {
            return res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        } else {
            if (req.body.supervisorRole) {
                UserSites.findOne({ 'site': { $in: [new ObjectId(req.body.site)] } }, function (err, siteObject) {
                    if (err) {
                        return res.status(200).send({ status: responseStatus.queryError.code });
                    }
                    if (!siteObject) {
                        return res.status(200).send({
                            status: responseStatus.siteNotFound.code
                        });
                    }
                    /* Checking for Agency Representative*/
                    var query = { status: new ObjectId(Config.activeStatusId) };
                    query['_id'] = { $in: siteObject.user };
                    /* Read All Guards under supervisor */
                    User.find(query, function (err, userObjects) {
                        if (err) {
                            return res.status(200).send({ status: responseStatus.queryError.code });
                        }
                        if (!userObjects) {
                            return res.status(200).send({
                                status: responseStatus.accountNotFound.code
                            });
                        }
                        /* Find Unassigned Guards */
                        getUnassignedDutyGuards(req.body.site, req.body.date, userObjects, req.body.duty, function (response) {
                            return res.status(200).send(response);
                        });
                    }).select('_id first_name last_name').sort([['first_name', 'ascending'], ['last_name', 'ascending']]);
                }).select('user');
            } else {
                /* Read Site users and filter site guards */
                SiteUser.findOne({ 'site': new ObjectId(req.body.site), status: new ObjectId(Config.activeStatusId) }, function (err, siteObject) {
                    if (err) {
                        return res.status(200).send({ status: responseStatus.queryError.code });
                    }
                    if (!siteObject) {
                        return res.status(200).send({
                            status: responseStatus.siteNotFound.code
                        });
                    }
                    /* Checking for Agency Representative*/
                    var query = { 'reporting_to': new ObjectId(req.body.supervisorId), status: new ObjectId(Config.activeStatusId) };
                    if (!req.body.agencyRepresentative) {
                        query['_id'] = { $in: siteObject.user };
                    }
                    /* Read All Guards under supervisor */
                    User.find(query, function (err, userObjects) {
                        if (err) {
                            return res.status(200).send({ status: responseStatus.queryError.code });
                        }
                        if (!userObjects) {
                            return res.status(200).send({
                                status: responseStatus.accountNotFound.code
                            });
                        }
                        /* Find Unassigned Guards */
                        getUnassignedDutyGuards(req.body.site, req.body.date, userObjects, req.body.duty, function (response) {
                            return res.status(200).send(response);
                        });
                    }).select('_id first_name last_name').sort([['first_name', 'ascending'], ['last_name', 'ascending']]);
                }).select('user');
            }
        }
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
        });
    }
}
/* Find Guards under supervisor who is not assigned to any Duty*/
function getUnassignedDutyGuards(site, date, allGuards, duty, callback) {
    /* Find All Guards under supervisor ids */
    var allGuardIds = Common.readUserIds(allGuards);
    /* Find Duty Assigned Guards */
    var timeObject = Common.getStartAndEndTime(date);
    DutyChart.find({ status: { $in: [new ObjectId(Config.activeStatusId), new ObjectId(Config.onleaveStatusId)] }, site: { $in: [new ObjectId(site)] }, user: { $in: allGuardIds }, date: { "$gte": timeObject.dayStartTime / 1000, "$lte": timeObject.dayEndTime / 1000 } }, function (dutyErr, dutyList) {
        if (dutyErr) {
            return callback({ status: responseStatus.queryError.code });
        }
        if (dutyList.length === 0) {
            return callback({ status: responseStatus.successResponse.code, data: allGuards, size: allGuards.length });
        }
        /* List all Unassigned duty Guards */
        var unAssignedGuards = [];
        var tempGuard;
        /* Loop through Guards under supervisor */
        for (var i = 0; i < allGuards.length; i++) {
            tempGuard = false;
            /* Loop through Duty Assigned guards */
            for (var j = 0; j < dutyList.length; j++) {
                if (allGuards[i]._id.toString() === dutyList[j].user.toString()) {
                    try {
                        /* Check each guard for each duty */
                        if (Config.onleaveStatusId === dutyList[j].status.toString()) {
                            tempGuard = true;
                            break;
                        } else if (dutyList[j].duty.toString() === duty) {
                            tempGuard = true;
                            break;
                        }
                    } catch (e) {
                        console.log(e);
                    }
                }
            }
            /* Find duty assigned guards */
            if (tempGuard === false) {
                unAssignedGuards.push(allGuards[i]);
            }
        }
        return callback({ status: responseStatus.successResponse.code, data: unAssignedGuards, size: unAssignedGuards.length });
    }).select('user duty status');
}

/* Find Supervisor dutys */
function getSupervisorDutyUnassignedSites(sites, date, supervisor, res) {
    /* Find All Supervisor unassigned sites*/
    var timeObject = Common.getStartAndEndTime(date);
    var allSiteIds = Common.readUserIds(sites);
    var dutyObj = {

        sites: function (callback) {
            DutyChart.find({status: {$in: [new ObjectId(Config.activeStatusId), new ObjectId(Config.onleaveStatusId)]}, site: {$in: allSiteIds}, user: supervisor, date: {"$gte": timeObject.dayStartTime / 1000, "$lte": timeObject.dayEndTime / 1000}}, function (dutyErr, dutyList) {
                if (dutyErr) {
                    callback({status: responseStatus.queryError.code});
                }
                if (dutyList.length === 0) { 
                    callback(null, {unAssignedSites: sites});
                } else {
                    /* List all Unassigned sites */
                    var unAssignedSites = [];
                    var flag=false;
                    for (var j = 0; j < dutyList.length; j++) {
                        flag=false;
                        try {
                            /* Check each chart for each duty */
                            if (Config.onleaveStatusId === dutyList[j].status.toString()) {
                               return callback(null, {unAssignedSites: []});
                            } else {
                                for (var k = 0; k < sites.length; k++) {
                                    if (sites[k]._id.toString() === dutyList[j].site[0]._id.toString()) { 
                                        flag=true;
                                    }
                                }
                                if(flag===false){
                                  unAssignedSites.push(dutyList[j].site[0]);   
                                } 
                            }
                        } catch (e) {
                            console.log(e);
                        }
                    }
                    callback(null, {unAssignedSites: unAssignedSites});
                }
            }).select('duty status site').populate([{
                    path: 'site',
                    select: '_id name'
                }]);
        },
        duty: function (callback) {
            /* Read All Guards under supervisor */
            Duty.find({site: {$in: allSiteIds}, status: new ObjectId(Config.activeStatusId)}, function (err, dutys) {
                if (err) {
                    callback(err);
                }
                callback(null, dutys);
            }).select('name site').sort({name: 1});
        }
    };
    Async.parallel(dutyObj, function (err, results) {
        try {
            if (err) {
                return res.status(200).send({
                    status: responseStatus.queryError.code
                });
            }
            return res.status(200).send({status: responseStatus.successResponse.code,results});
        } catch (e) {
            return res.status(200).send({
                status: responseStatus.exceptionError.code
            });
        }
    });
}

/**
 * Read Supervisor where site is not assigned to any duty
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.readDutyUnassignedSupervisors = function (req, res, next) {
    try {
        if (!req.body.supervisorId || !req.body.date) {
            return res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        } else {
            UserSites.findOne({'user': new ObjectId(req.body.supervisorId)}, function (err, siteObject) {
                if (err) {
                    return res.status(200).send({status: responseStatus.queryError.code});
                }
                if (!siteObject) {
                    return res.status(200).send({
                        status: responseStatus.siteNotFound.code
                    });
                }

                /* Find Unassigned Sites */
                getSupervisorDutyUnassignedSites(siteObject.site, req.body.date, req.body.supervisorId, res);
            }).select('site').populate([{
                    path: 'site',
                    select: '_id name'
                }]);
        }
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
        });
    }
}

/**
 * Read Guards who is not assigned to any duty
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.readDutyassignedGuards = function (req, res, next) {
    try {
        if (!req.body.site || !req.body.supervisorId || !req.body.date) {
            return res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        } else {
            /* Find Duty Assigned Guards */
            if (req.body.role === Config.client) {
                Client.findOne({ representId: new ObjectId(req.body.supervisorId) }, function (clientErr, clientObject) {
                    if (clientErr) {
                        return res.status(200).send({
                            status: responseStatus.queryError.code
                        });
                    }
                    if (!clientObject) {
                        return res.status(200).send({
                            status: responseStatus.objectNotFound.code
                        });
                    }
                    SiteUser.findOne({ 'client': clientObject._id, 'site': new ObjectId(req.body.site) }, function (err, userObjects) {
                        if (err) {
                            return res.status(200).send({ status: responseStatus.queryError.code });
                        }
                        if (!userObjects) {
                            return res.status(200).send({
                                status: responseStatus.accountNotFound.code
                            });
                        }
                        processreadDutyassignedGuards(req, res, userObjects.user);
                    }).select('user').populate([{
                        path: 'user',
                        select: '_id'
                    }]);
                }).select('_id').lean();
            } else {
                User.find({ 'reporting_to': new ObjectId(req.body.supervisorId) }, function (err, userObjects) {
                    if (err) {
                        return res.status(200).send({ status: responseStatus.queryError.code });
                    }
                    if (!userObjects) {
                        return res.status(200).send({
                            status: responseStatus.accountNotFound.code
                        });
                    }
                    processreadDutyassignedGuards(req, res, userObjects);
                }).select('_id');
            }
        }
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
        });
    }
}

function processreadDutyassignedGuards(req, res, userObjects) {
    getAssignedDutyGuards(req.body.site, req.body.date, userObjects, function (usersDuty) {
        if (usersDuty.status === responseStatus.successResponse.code) {
            /* Read Users ids */
            var userIds = [];
            usersDuty.usersDt.forEach(function (duty) {
                userIds.push(duty.user._id);
            });
            readUserCurrentLocations(userIds, function (response) {
                return res.status(200).send(response);
            });
        } else {
            return res.status(200).send(usersDuty);
        }
    });
}


/* Find Guards under supervisor who is assigned to Duty*/
function getAssignedDutyGuards(site, date, userList, callback) {
    var timeObject = Common.getStartAndEndTime(date);
    /* Find All Guards under supervisor ids */
    var allGuardIds = Common.readUserIds(userList);
    DutyChart.find({ site: { $in: [new ObjectId(site)] }, leave: null, user: { $in: allGuardIds }, date: { "$gte": timeObject.dayStartTime / 1000, "$lte": timeObject.dayEndTime / 1000 } }, function (dutyErr, dutyList) {
        if (dutyErr) {
            return callback({ status: responseStatus.queryError.code });
        }
        if (dutyList.length === 0) {
            return callback({ status: responseStatus.emptyDutychart.code });
        }
        return callback({ status: responseStatus.successResponse.code, usersDt: dutyList });
    }).select('user').populate([{
        path: 'user',
        select: '_id'
    }]);
}



/**
 * User Read By Id along with respective select data
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.readuserById = function (req, res, next) {
    try {
        if (!req.body.id) {
            res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        } else {
            User.findById(req.body.id, function (err, data) {
                if (err)
                    return res.status(200).send({ status: responseStatus.queryError.code });
                return res.status(200).send({ data: data, status: responseStatus.successResponse.code });
            }).select('-created_at').populate([{
                path: 'agency',
                select: 'name'
            }, {
                path: 'reporting_to',
                select: 'first_name last_name'
            },
            {
                path: 'role',
                select: 'name'
            },
            {
                path: 'status',
                select: 'name'
            },
            ]);
            ;
        }
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
            , description: exception
        });
    }
}

/**
 * User Find by Id  and update  entry in collection. returns success or error messages
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */

exports.userUpdate = function (req, res, next) {
    try {
        if (!req.body.first_name || !req.body.last_name || !req.body.status || !req.body.mobile || !req.body.email || !req.body.agency || !req.body.role || !req.body._id) {
            return res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        } else {
            /* checking whether the mobile or email id is using another user*/
            User.findOne({
                _id: {
                    $ne: new ObjectId(req.body._id)
                },status:new ObjectId(Config.activeStatusId),
                $or: [
                    { email: req.body.email }, { 'contact_info.mobile': req.body.mobile }]
            }, function (err, userObject) {
                if (err) {
                    return res.status(200).send({
                        status: responseStatus.queryError.code
                    });
                }
                /* If a user with email does exist return an error */
                if (userObject) {
                    if (userObject.email === req.body.email) {
                        return res.status(200).send({
                            status: responseStatus.emailExist.code
                        });
                    }
                    if (userObject.contact_info.mobile === req.body.mobile) {
                        return res.status(200).send({
                            status: responseStatus.phoneExist.code
                        });
                    }
                }
                req['body']['contact_info'] = { 'mobile': req.body.mobile, 'alternative_no': req.body.alternative_no };
                req['body']['current_address'] = { 'zipcode': req.body.currentAddressZipCode, 'address2': req.body.currentAddress2, 'address1': req.body.currentAddress1 };
                req['body']['permanent_address'] = { 'zipcode': req.body.permanentAddressZipCode, 'address2': req.body.permanentAddress2, 'address1': req.body.permanentAddress1 };
                if (!Common.isNullOrEmpty(req.body.storage)) {
                    req['body']['avatar'] = req.body.storage;
                } else {
                    delete req['body']['avatar'];
                }
                /* If a user email or mobile does not exist, update user record */
                User.findByIdAndUpdate(req.body._id, { $set: req.body }, { new: false }, function (err, updatedObject) {
                    /* On  Update Error*/
                    if (err) {
                        return res.status(200).send({
                            status: responseStatus.queryError.code
                        });
                    }
                    if (req.body.role === Config.roleSupervisorId) {
                        if (req.body.old_mobile !== req.body.mobile) {
                            sendNotificationToSupervisorGuardsOnPhoneChange(updatedObject, req.body.mobile, function (usersDuty) {
                                return res.status(200).send({
                                    status: responseStatus.successResponse.code
                                });
                            });
                        } else {
                            return res.status(200).send({
                                status: responseStatus.successResponse.code
                            });
                        }
                    } else {
                        return res.status(200).send({
                            status: responseStatus.successResponse.code
                        });
                    }
                });
            });
            /* End for checking mobile or emailid*/

        }
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
        });
    }
}


function sendNotificationToSupervisorGuardsOnPhoneChange(supervisor, mobile, callback) {
    User.find({ 'reporting_to': supervisor._id }, function (err, users) {
        if (err) {
            return callback({ status: responseStatus.queryError.code });
        }
        var tokens = [];
        users.forEach(function (user) {
            try {
                if (tokens.indexOf(user.deviceId) === -1 && !Common.isNullOrEmpty(user.deviceId)) {
                    tokens.push(user.deviceId);
                }
            } catch (e) {
            }
        });
        try {
            if (tokens.length === 0) {
                return callback({ status: responseStatus.successResponse.code });
            } else {
                var message = supervisor.first_name + " " + supervisor.last_name + " has changed mobile number";
                Common.broadCastNotification(tokens, message, { payload: "{'mobile':'" + mobile + "'}", type: "ChangeReporterMobile", title: "Reportee Mobile has changed" }, function (response) {
                    return callback({ status: responseStatus.queryError.code });
                });
            }
        } catch (e) {
            return callback({ status: responseStatus.successResponse.code });
        }

    });
}


/**
 * Accepts Site fields and adds entry in collection. returns success or error messages
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.readMyGuards = function (req, res, next) {
    try {
        if (!req.body.reporting_to) {
            return res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        } else {
            if (req.body.site) {
                if (req.body.role === Config.client) {
                    Client.findOne({ representId: new ObjectId(req.body.reporting_to) }, function (clientErr, clientObject) {
                        if (clientErr) {
                            return res.status(200).send({
                                status: responseStatus.queryError.code
                            });
                        }
                        if (!clientObject) {
                            return res.status(200).send({
                                status: responseStatus.objectNotFound.code
                            });
                        }
                        findSiteUserAndProceed(req, res, { 'client': clientObject._id, 'site': new ObjectId(req.body.site) });
                    }).select('_id').lean();
                } else {
                    findSiteUserAndProceed(req, res, { 'site': new ObjectId(req.body.site) });
                }
            } else {
                readMyGuardsUsers(res, { reporting_to: new ObjectId(req.body.reporting_to) });
            }
        }
    } catch (exception) {
        console.log(exception);
        return res.status(200).send({
            status: responseStatus.exceptionError.code
        });
    }
}

function findSiteUserAndProceed(req, res, query) {
    SiteUser.findOne(query, function (err, siteObject) {
        if (err) {
            return res.status(200).send({ status: responseStatus.queryError.code });
        }
        if (!siteObject) {
            return res.status(200).send({
                status: responseStatus.siteNotFound.code
            });
        }
        readMyGuardsUsers(res, { _id: { $in: siteObject.user } });
    }).select('user');
}

function readMyGuardsUsers(res, query) {
    User.find(query, function (err, userObjects) {
        if (err) {
            return res.status(200).send({ status: responseStatus.queryError.code });
        }
        if (!userObjects) {
            return res.status(200).send({
                status: responseStatus.objectNotFound.code
            });
        }

        readUserCurrentLocations(Common.readIds(userObjects), function (response) {
            return res.status(200).send(response);
        });
    }).select('_id');
}

/* Read User Current Location*/
function readUserCurrentLocations(users, callback) {
    /* Check for attendance if he is forgot to signout */
    var timeObject = Common.getStartAndEndTime(Math.floor(Date.now() / 1000));
    console.log({ status: new ObjectId(Config.activeStatusId), 'user': { $in: users }, 'date': { "$gte": timeObject.dayStartTime / 1000, "$lte": timeObject.dayEndTime / 1000 } });
    Attendance.find({ status: new ObjectId(Config.activeStatusId), 'user': { $in: users }, 'date': { "$gte": timeObject.dayStartTime / 1000, "$lte": timeObject.dayEndTime / 1000 } }, function (err, attendanceList) {
        if (err) {
            return callback({ status: responseStatus.queryError.code });
        }
        mapSignedInwithGuards(attendanceList, users, function (response) {
            return callback(response);
        });
    }).select('duty user').populate([{
        path: 'user',
        select: '_id'
    }]);
}

function mapSignedInwithGuards(attendanceList, users, callback) {
    UserCurrentLocation.find({ 'user': { $in: users } }, function (err, userCurrentLocation) {
        if (err) {
            return callback({ status: responseStatus.queryError.code });
        }
        /* Map user current location */
        var todayGuardPreset = false;
        for (var userLocation = 0; userLocation < userCurrentLocation.length; userLocation++) {
            todayGuardPreset = false;
            for (var attendance = 0; attendance < attendanceList.length; attendance++) {
                try {
                    if (attendanceList[attendance].user._id.toString() === userCurrentLocation[userLocation].user._id.toString() && (attendanceList[attendance].duty[0].presence === 'P') || (attendanceList[attendance].duty[1].presence === 'P')) {
                        todayGuardPreset = true;
                        break;
                    }
                } catch (e) {
                    console.log(e);
                    todayGuardPreset = false;
                }
            }
            if (todayGuardPreset === false) {
                userCurrentLocation[userLocation]['lat'] = null;
                userCurrentLocation[userLocation]['lon'] = null;
            }
        }
        return callback({ data: Common.sortUsers(userCurrentLocation), status: responseStatus.successResponse.code });
    }).select('lat lon user').populate([{
        path: 'user',
        select: 'first_name last_name contact_info.mobile userid avatar'
    }]).lean();
}

function checkAgencyPackageLimit(agency, callback) {
    Agency.findById(agency, function (err, agencyObject) {
        if (err) {
            return callback({ status: responseStatus.queryError.code });
        }
        if (!agencyObject) {
            return callback({
                status: responseStatus.objectNotFound.code
            });
        }
        User.count({ agency: new ObjectId(agency) }, function (err, count) {
            if (err) {
                return callback({ status: responseStatus.queryError.code });
            }
            var eligibleTotalCount=Number(agencyObject.package.grant_plus) + Number(agencyObject.package.user_count);
            console.log("total cooo"+eligibleTotalCount+"existed count"+count);
            //console.log("total count"+(Number(agencyObject.package.grant_plus) + Number(agencyObject.package.user_count)));
            if (eligibleTotalCount >= count) {
                console.log("i mam here  count"+count+"object user count"+agencyObject.package.grant_plus+"packagecount"+agencyObject.package.user_count);
                return callback({ status: responseStatus.successResponse.code });
            } else {
                console.log("i mam else part@@@@ count"+count+"object user count"+agencyObject.package.grant_plus+"packagecount"+agencyObject.package.user_count);
                return callback({ status: responseStatus.packageLimitExceeded.code });
            }
        });
    }).select('package').populate([{
        path: 'package',
        select: 'grant_plus user_count'
    }]);
}

/**
 * Mail Or SMS pagination with search name filter
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.readUsersForMessage = function (req, res, next) {
    var query = { status: new ObjectId(Config.activeStatusId) };
    if (req.body.dataFor === Config.agency) {
        query['agency'] = new ObjectId(req.body.agency);
        Common.readRoles([Config.client], function (roleIds) {
            console.log(roleIds)
            query['role'] = { $in: roleIds };
            processMessageUsers(query, res);
        });
    } else {
        Common.readRoles([Config.agency], function (roleIds) {
            query['role'] = { $in: roleIds };
            processMessageUsers(query, res);
        });
    }

}

function processMessageUsers(query, res) {
    try {
        User.find(query, function (err, data) {
            if (err) {
                return res.status(200).send({ status: err });
            }
            return res.status(200).send({ status: responseStatus.successResponse.code, data: data });
        }).select('email contact_info.mobile first_name last_name');
    } catch (e) {
        console.log(e);
    }
}


/**
 * Read Supervisor where site is not assigned to any duty used for edit supervisor duty roaster
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */
exports.readDutyAllUnassignedSupervisors = function (req, res, next) {
    try {
        if (!req.body.supervisorId || !req.body.date) {
            return res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        } else {
            UserSites.findOne({'user': new ObjectId(req.body.supervisorId)}, function (err, siteObject) {
                if (err) {
                    return res.status(200).send({status: responseStatus.queryError.code});
                }
                if (!siteObject) {
                    return res.status(200).send({
                        status: responseStatus.siteNotFound.code
                    });
                }

                /* Find Unassigned Sites */
                getSupervisorDutyAllUnassignedSites(siteObject.site, req.body.date, req.body.supervisorId, res);
            }).select('site').populate([{
                    path: 'site',
                    select: '_id name'
                },
            ]);
        }
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
        });
    }
}


/* Find Supervisor dutys */
function getSupervisorDutyAllUnassignedSites(sites, date, supervisor, res) {
    /* Find All Supervisor unassigned sites*/
    var timeObject = Common.getStartAndEndTime(date);
    var allSiteIds = Common.readUserIds(sites);
    var dutyObj = {

        sites: function (callback) {
            DutyChart.find({status: {$in: [new ObjectId(Config.activeStatusId), new ObjectId(Config.onleaveStatusId)]}, site: {$in: allSiteIds}, user: supervisor, date: {"$gte": timeObject.dayStartTime / 1000, "$lte": timeObject.dayEndTime / 1000}}, function (dutyErr, dutyList) {
                if (dutyErr) {
                    callback({status: responseStatus.queryError.code});
                }
                if (dutyList.length === 0) { 
                    callback(null, {unAssignedSites: sites});
                } else {
                  //   List all Unassigned sites 
                    var unAssignedSites = [];
                    var flag=false;
                    for (var j = 0; j < dutyList.length; j++) {
                        flag=false;
                        try {
                            //Check each chart for each duty 
                            if (Config.onleaveStatusId === dutyList[j].status.toString()) {
                               return callback(null, {unAssignedSites: []});
                            } else {
                                for (var k = 0; k < sites.length; k++) {
                                    if (sites[k]._id.toString() === dutyList[j].site[0]._id.toString()) { 
                                        flag=true;
                                    }
                                }
                                if(flag===false){
                                  unAssignedSites.push(dutyList[j].site[0]);   
                                } 
                            }
                        } catch (e) {
                            console.log(e);
                        }
                    }
                    callback(null, {unAssignedSites: unAssignedSites});
                }
            }).select('duty status site').populate([{
                    path: 'site',
                    select: '_id name'
                },{
                    path:'duty',
                    select:'name start_time end_time'

                }]);
        },
        duty: function (callback) {
            /* Read All Guards under supervisor */
            Duty.find({site: {$in: allSiteIds}, status: new ObjectId(Config.activeStatusId)}, function (err, dutys) {
                if (err) {
                    callback(err);
                }
                callback(null, dutys);
            }).select('name site start_time end_time').populate([{
                path: 'site',
                select: '_id name'
            }]).sort({name: 1});
        }
    };
    Async.parallel(dutyObj, function (err, results) {
        try {
            if (err) {
                return res.status(200).send({
                    status: responseStatus.queryError.code
                });
            }
            return res.status(200).send({status: responseStatus.successResponse.code,results});
        } catch (e) {
            return res.status(200).send({
                status: responseStatus.exceptionError.code
            });
        }
    });
}


/**
 * Read guard patrolling based on date and guard id
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */

exports.readPatrollingsBasedOnUserAndDate = function (req, res, next) {
    try {
        if (!req.body.site || !req.body.date) {
            return res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        } else {
            var timeObject = Common.getStartAndEndTime(req.body.date);
            UserPatrolling.find({'site': new ObjectId(req.body.site),date: { "$gte": timeObject.dayStartTime / 1000, "$lte": timeObject.dayEndTime / 1000 }}, function (err, Objects) {
                if (err) {
                    return res.status(200).send({status: responseStatus.queryError.code});
                }
                if (!Objects) {
                    return res.status(200).send({
                        status: responseStatus.objectNotFound.code
                    });
                }
                var patrolIds=[];
               // console.log(" Patrolling objects"+JSON.stringify(Objects));
                for(var patrol of Objects){
                     // console.log("patrolinfo"+JSON.stringify(patrol));
                       for(var patrolinfo of patrol.patrolling){
                         patrolIds.push(patrolinfo._id);
                       }
                   }  
                  // console.log("patroli ids"+JSON.stringify(patrolIds));
                    
                   PatrollingList.count({patrolling:{$in:patrolIds},created_at: { "$gte": timeObject.dayStartTime / 1000, "$lte": timeObject.dayEndTime / 1000 },status:Config.completedStatusId}, function (err, count) {
                     //   console.log("count"+count);
                        return res.status(200).send({status: responseStatus.successResponse.code,data:Objects,completedRoutes:count});
                   });   
              
            }).select('patrolling name').populate([{
                    path: 'patrolling',
                    select: '_id patrolling_route name',
                    populate: [{path:'patrolling_route',select:'name'}]
                },
            ]);
        }
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
        });
    }
}




/**
 * Read guard patrolling based on date and guard id and patrol id
 * @param JSON req - post data
 * @param JSON res - sending the resulted data
 * @param JSON next - callback for specific error handling
 * @returns response
 */

exports.readCompletedPatrollingRoute = function (req, res, next) {
    try {
        if (!req.body.site || !req.body.date) {
            return res.status(200).send({
                status: responseStatus.fieldsRequired.code
            });
        } else {
            var timeObject = Common.getStartAndEndTime(req.body.date);
            PatrollingList.findOne({'site': new ObjectId(req.body.site),created_at: { "$gte": timeObject.dayStartTime / 1000, "$lte": timeObject.dayEndTime / 1000 },patrolling:new ObjectId(req.body.patrolId)}, function (err, Objects) {
                if (err) {
                    return res.status(200).send({status: responseStatus.queryError.code});
                }
                if (!Objects) {
                    return res.status(200).send({
                        status: responseStatus.objectNotFound.code
                    });
                }
              //  console.log("objects"+JSON.stringify(Objects));
                return res.status(200).send({status: responseStatus.successResponse.code,data:Objects});   
            }).select('patrolling_completed route user').populate([{
                path: 'patrolling',
                select: '_id patrolling_route name',
                populate: [{path:'patrolling_route',select:'name patrolling_points' }]
            },{
                path:'user',
                select:'first_name last_name'
            }
        ]);
        }
    } catch (exception) {
        return res.status(200).send({
            status: responseStatus.exceptionError.code
        });
    }
}