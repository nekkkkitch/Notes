var passwordInput=document.getElementById("passwordInput");
var passwordProblem=document.getElementById("passwordProblem");
var passwordStrength=0;


function CheckPassword(){
    password = document.getElementById("passwordInput").value;
    if (password.length > 16){
        passwordProblem.textContent="Too much characters";
        return;
    }
    if(password.length < 8){
        passwordProblem.textContent="Not enough characters";
        return;
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
}