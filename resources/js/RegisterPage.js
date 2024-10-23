var passwordInput=document.getElementById("passwordInput");
var passwordProblem=document.getElementById("passwordProblem");
var loginProblem = document.getElementById("loginProblem")
var passwordStrength=0;
var smalllat = "qwertyuiopasdfghjklzxcvbnm"
var biglat = "QWERTYUIOPASDFGHJKLZXCVBNM"
var nums = "1234567890"
var specs = "!@#$%^&*()"
var loginAlph = smalllat+biglat+nums
var passwordAlph = loginAlph+specs
UpdateButtonCondition()
function CheckLogin(){
    login = document.getElementById("loginInput").value
    if(login.length > 16){
        loginProblem.textContent="Too much characters";
        return false;
    }
    if(login.length < 8){
        loginProblem.textContent="Not enough characters";
        return false;
    }
    for(var i = 0;i<login.length;i++){
        if(loginAlph.charAt(login[i])==-1){
            loginInput.textContent = "WrongCharacters"
            return false;
        }
    }
    loginProblem.textContent=""
    return true;
}

function CheckPassword(){
    password = document.getElementById("passwordInput").value;
    if (password.length > 16){
        passwordProblem.textContent="Too much characters";
        return false;
    }
    if(password.length < 8){
        passwordProblem.textContent="Not enough characters";
        return false;
    }

    for(var i = 0;i<password.length;i++){
        if(passwordAlph.charAt(password[i])==-1){
            passwordInput.textContent = "WrongCharacters"
            return false;
        }
    }
    var passwordHasNums = false;
    var passwordHasSmallAlph = false;
    var passwordHasBigAlph = false;
    var passwordHasSpecs = false;
    for(var i=0;i<password.length;i++){
        if(password[i].match(/[a-z]/)){
            passwordHasSmallAlph = true;
        }
        if(password[i].match(/[A-Z]/)){
            passwordHasBigAlph = true;
        }
        if(password[i].match(/[0-9]/)){
            passwordHasNums = true;
        }
        if(password[i].match(/[!@#$%^&*()]/i)){
            passwordHasSpecs = true;
        }
    }
    passwordStrength=0;
    if(passwordHasBigAlph){
        passwordStrength+=1;
    }
    if(passwordHasSmallAlph){
        passwordStrength+=1;
    }
    if(passwordHasNums){
        passwordStrength+=1;
    }
    if(passwordHasSpecs){
        passwordStrength+=2;
    }
    passwordProblem.textContent="Password strength is "+(passwordStrength*20).toString()+"% strong";
    return true;
}

function UpdateButtonCondition(){
    var button = document.getElementById("registerButton")
    button.disabled=!(CheckPassword() && CheckLogin()) 
}

async function SendRegistrationData(){
    var login = document.getElementById("loginInput").value
    var password = document.getElementById("passwordInput").value
    let response = await fetch('/register-user', {
        method:'POST',
        headers:{
            'Content-type':'application/json'
        },
        body: JSON.stringify({"login":login,"password":password})
    })
    let commit = await response.json()
    if(commit.occupied){
        loginProblem.textContent="Login is occupied"
    }
    else{
        var accessToken = commit.accessToken
        var refreshToken = commit.refreshToken
        document.cookie = encodeURIComponent("accessToken") + "=" + encodeURIComponent(accessToken)
        document.cookie = encodeURIComponent("refreshToken") + "=" + encodeURIComponent(refreshToken)
        window.location.replace("http://localhost:8080")
    }
}

