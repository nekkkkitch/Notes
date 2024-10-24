class Note{
    constructor(id, title, description, user_id){
        this.id = id
        this.title = title
        this.description = description
        this.user_id = user_id
    }
}

document.getElementById("popupMenu").hidden = true;
GetNotes()

function ShowPanel(){
    document.getElementById("popupMenu").hidden = !document.getElementById("popupMenu").hidden;
}

async function GetNotes(){
    var accessToken = getCookie("accessToken")
    var refreshToken = getCookie("refreshToken")
    let response = await fetch('/get-notes', {
        method:'GET',
        headers:{
            'x-access-token':accessToken,
            'x-refresh-token':refreshToken
        }
    })
    let commit = await response.json()
    var status = document.getElementById("status")
    switch(commit.status){
        case "User is not identified":
            status.textContent = "Вы не вошли в аккаунт"
            break
        case "Invalid token":
            status.textContent = "Токен был изменён, перезайдите в аккаунт"
            break
        case "Expired token":
            status.textContent = "Истёк срок логина. Авторизируйтесь снова"
            break
        case "Success with tokens":
            var accessToken = commit.accessToken
            var refreshToken = commit.refreshToken
            document.cookie = encodeURIComponent("accessToken") + "=" + encodeURIComponent(accessToken)
            document.cookie = encodeURIComponent("refreshToken") + "=" + encodeURIComponent(refreshToken)
            ParseNotes(commit.notes)
            break
        case "Success":
            ParseNotes(commit.notes)
            break
    }
}

function ParseNotes(notes){
    var parsedNotes =JSON.parse(atob(notes))
    for(let i = 0; i < parsedNotes.length; i++){
        console.log(parsedNotes[i].Title + ": " + parsedNotes[i].Description)
    }
}

function getCookie(cname) {
    let name = cname + "=";
    let decodedCookie = decodeURIComponent(document.cookie);
    let ca = decodedCookie.split(';');
    for(let i = 0; i <ca.length; i++) {
      let c = ca[i];
      while (c.charAt(0) == ' ') {
        c = c.substring(1);
      }
      if (c.indexOf(name) == 0) {
        return c.substring(name.length, c.length);
      }
    }
    return "";
}

