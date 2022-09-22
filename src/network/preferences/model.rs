fn get_and_update_last_ds()->String{
    let mut prefs: ServerPreferences = cypherpost::storage::read_prefs().unwrap_or(ServerPreferences{
        last_ds: "m/1h/0h".to_string(),
        server: "localhost:3021".to_string()
    });
    let last_ds = prefs.last_ds;
    let mut split_ds: Vec<String> = last_ds.replace("h","").replace("'","").split("/").map(|s| s.to_string()).collect();
    let rotator = split_ds.pop().unwrap().parse::<u64>().unwrap() + 1;
    let join: String = split_ds.into_iter().map(|val| {
        if val == "m" { val + "/"} 
        else { val + "h/" }
    }).collect();
    let new_ds = join + &rotator.to_string() + "h";
    
    prefs.last_ds = new_ds.clone();
    cypherpost::storage::create_prefs(prefs).unwrap();
    new_ds

}