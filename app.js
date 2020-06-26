//Using Qlik Sense self-signed certificates requires to add reject unauthorized.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const https = require('https');
const path = require('path');
const fs = require('fs-extra');
const nodemailer = require('nodemailer');

//########## CONFIGURATION ##########\\
//How often to check the Qlik Sense reload tasks (0.1 = every 6th second)
var minutes = 0.1, the_interval = minutes * 60 * 1000; //Change Here
var relativeUsed;

//Change if you want to specify another username than the internal scheduler to perform the actions.
const userDirectory = 'xxx'; //Change Here, Add user directory
const userId = 'xxx'; //Change Here, Add user with access
const host = 'localhost';
const certificatesPath='C:/ProgramData/Qlik/Sense/Repository/Exported Certificates/.Local Certificates/';
const xrfkey = 'abcdefghijklmnop';
const readCert = filename => fs.readFileSync(path.resolve(__dirname, certificatesPath, filename));

const ruleConditionLimitUsers='!user.IsAnonymous()'; //After "limitUsersAfter" is hit, disable anonymous users.
const ruleConditionUnlimitUsers='true'; //Allow all users to use capacity minutes, including anonymous.
const limitUsersAfter=77; //Change Here, Add your limit here (used percentage of total available mintues)

//########## Email CONFIGURATION ##########
const fromEmail = 'xxx@outlook.com'; //Change Here, Add Mails here sender address (who sends)
const toEmail = 'xxx@qlik.com, xxx@qlik.com'; //Change Here, Add Mails here list of receivers (who receives)
const subject = 'Qlik Analyzer Capacity License Alert!'; //Change Here, Add Subject here Subject line

var transporter = nodemailer.createTransport({
    host: "smtp-mail.outlook.com", // Change Here, Add mail host here, check this for help https://ourcodeworld.com/articles/read/264/how-to-send-an-email-gmail-outlook-and-zoho-using-nodemailer-in-node-js
    secureConnection: false, // TLS requires secureConnection to be false
    port: 587, // port for secure SMTP
    tls: {
       ciphers:'SSLv3'
    },
    auth: {
        user: fromEmail, // Change Here, Add user account
        pass: 'xxx' // Change Here, Add user password
    }
});
const requestOptions = {
	rejectUnauthorized: false,
	  method: 'GET',
	  host: host,
	  ca: [readCert('root.pem')],
	  key: readCert('client_key.pem'),
	  cert: readCert('client.pem'),
	  headers: {
		'Content-Type': 'application/json',
		'X-Qlik-User': `UserDirectory=${encodeURIComponent(userDirectory)}; UserId=${encodeURIComponent(userId)}`,
		'X-Qlik-Xrfkey': xrfkey,
    },
};
async function getRemainingTime(){
	return new Promise(async (res, rej) => {
		qrsObj({port:4242,path:'/qrs/license/analyzertimeaccesstype/full?Xrfkey='+xrfkey,method:"GET"})
			.then((licenses) => {
				res(licenses);
			})
	})
}
async function checkLicenses(){
	return new Promise(async (res, rej) => {
		var remainingTime=await getRemainingTime();
		remainingTime.forEach(function(r) {
			relativeUsed=((r.usedMinutes/r.assignedMinutes)*100);
			console.log('TOTAL:',relativeUsed+'% used,','Remaining',r.remainingMinutes,'minutes, Used',r.usedMinutes,'minutes, Total',r.assignedMinutes + ' minutes');
		})
		qrsObj({port:4242,path:'/qrs/license/analyzertimeaccessusage/full?Xrfkey='+xrfkey,method:"GET"})
		.then((r) => {
			r.forEach(function(s) {
				var start = new Date(s.useStartTime);
				var stop = new Date(s.useStopTime);
				console.log(s.user.userDirectory+"\\"+s.user.userId,((stop-start)/1000/60),' minutes');
			})
		})
		.then(function(){			
			qrsObj({port:4242,path:"/qrs/systemrule/full?filter=name%20eq%20'Security%20rule%20for%20AnalyzerTimeAccessType'%20&Xrfkey="+xrfkey,method:"GET"})
			.then((rules) => {
				rules.forEach(function(rule) {
					console.log(rule);
					if(relativeUsed<limitUsersAfter && rule.rule != ruleConditionUnlimitUsers)
						rule.rule=ruleConditionUnlimitUsers;
					else if(relativeUsed>limitUsersAfter && rule.rule != ruleConditionLimitUsers){
						rule.rule=ruleConditionLimitUsers;
						var mailOptions = {
							from: fromEmail,
							to: toEmail, 
							subject: subject,
							html: '<h2>Hi Admin!</h2><p>Security rules changed restricted Analyzer Capacity access; '+Math.round(relativeUsed*100)/100+'% currently used (limit set to '+limitUsersAfter+'%). It will be changed back first of next month.</p>' //Change Here, Add Mail content here; 
						};
						transporter.sendMail(mailOptions, function(error, info){
							if(error){
								return console.log(error);
							}
						
							console.log('Message sent: ' + info.response);
						});
					}
					else
						return;
					qrsObj({port:4242,path:"/qrs/systemrule/"+rule.id+"?Xrfkey="+xrfkey,method:"PUT",data:rule}).then((resp) => {
						console.log(resp);
					})
				})
			})			
		})
	})
}
async function qrsObj(obj){
  return new Promise(async (res, rej) => {	
	if(obj.data){
	obj.data = JSON.stringify(obj.data)
	}
	var options = {
		port: obj.port,
		path: obj.path
		};
	Object.assign(options,requestOptions);
	options.method=obj.method;
	const req = https.request(options, (resp) => {
	  console.log(`statusCode: ${resp.statusCode}`)
	  resp.on('data', (d) => {
		res(JSON.parse(d.toString()));
	  })
	})
	req.on('error', (error) => {
	  console.error(error)
	})
	if(obj.data)
		req.write(obj.data);
	req.end();
  })
}
setInterval(checkLicenses, the_interval);
checkLicenses();
