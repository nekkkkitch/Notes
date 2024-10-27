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
    if(CheckStatus(commit)){
        ParseNotes(commit.notes)
    }
}

async function AddNote(){
    window.location.replace("http://localhost:8080/addnote")
}

async function DeleteNote(id){
    var accessToken = getCookie("accessToken")
    var refreshToken = getCookie("refreshToken")
    let response = await fetch('/delete-note', {
        method:'DELETE',
        headers:{
            'x-access-token':accessToken,
            'x-refresh-token':refreshToken
        },
        body: JSON.stringify({
            'note_id':id
        })
    })
    let commit = await response.json()
    if(CheckStatus(commit)){
        document.getElementById("Note#"+id).remove()
    }
    //послать запрос на сервер на удаление нотеса из бд
    //если успешно удалилось, удалить тут
}

function CheckStatus(commit){
    var status = document.getElementById("status")
    switch(commit.status){
        case "User is not identified":
            status.textContent = "Вы не вошли в аккаунт"
            return false
        case "Invalid token":
            status.textContent = "Токен был изменён, перезайдите в аккаунт"
            return false
        case "Expired token":
            status.textContent = "Истёк срок логина. Авторизируйтесь снова"
            return false
        case "Success with tokens":
            var accessToken = commit.accessToken
            var refreshToken = commit.refreshToken
            document.cookie = encodeURIComponent("accessToken") + "=" + encodeURIComponent(accessToken)
            document.cookie = encodeURIComponent("refreshToken") + "=" + encodeURIComponent(refreshToken)
            return true
        case "Success":
            return true
    }
}

function ChangeNote(id){
    window.location.replace("http://localhost:8080/note?id="+id)
}

function GoToCreateNote(){
    window.location.replace("http://localhost:8080/addnote")
}

function ParseNotes(notes){
    var noteList = document.getElementById("notes")
    var note = document.querySelector('#baseNote')
    var parsedNotes =JSON.parse(atob(notes))
    for(let i = 0; i < parsedNotes.length; i++){    
        var clonnedNote = note.cloneNode(true)
        clonnedNote.id="Note#"+parsedNotes[i].ID
        for(let j = 0; j < clonnedNote.childNodes.length;j++){
            switch (clonnedNote.childNodes[j].id){
                case "noteInside":
                    var noteInside = clonnedNote.childNodes[j]
                    for(let k = 0; k < noteInside.childNodes.length;k++){
                        switch(noteInside.childNodes[k].id){
                            case "noteTitle":
                                noteInside.childNodes[k].textContent = parsedNotes[i].Title
                                break
                            case "noteDescription":
                                noteInside.childNodes[k].textContent = parsedNotes[i].Description
                                break
                        }
                    }
                    break
                case "imgs":
                    var imgs = clonnedNote.childNodes[j]
                    for(let k = 0; k < imgs.childNodes.length;k++){
                        switch(imgs.childNodes[k].id){
                            case "pencil":
                                imgs.childNodes[k].id = parsedNotes[i].ID
                                break
                            case "trashcan":
                                imgs.childNodes[k].id = parsedNotes[i].ID
                                break
                        }
                    }
                break
            }
            
        }
        note.after(clonnedNote)
    }
    note.remove()
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

function Exit(){
    document.cookie = encodeURIComponent("accessToken") + "=" + ""
    document.cookie = encodeURIComponent("refreshToken") + "=" + ""
    window.location.reload()
}