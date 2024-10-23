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

async function SendLoginData(){
    var login = document.getElementById("loginInput").value
    var password = document.getElementById("passwordInput").value
    let response = await fetch('/login-user', {
        method:'POST',
        headers:{
            'Content-type':'application/json'
        },
        body: JSON.stringify({"login":login,"password":password})
    })
    let commit = await response.json()
    if(commit.status != "gut"){
        loginProblem.textContent=commit.status
    }
    else{
        var accessToken = commit.accessToken
        var refreshToken = commit.refreshToken
        document.cookie = encodeURIComponent("accessToken") + "=" + encodeURIComponent(accessToken)
        document.cookie = encodeURIComponent("refreshToken") + "=" + encodeURIComponent(refreshToken)
        window.location.replace("http://localhost:8080")
    }
}

