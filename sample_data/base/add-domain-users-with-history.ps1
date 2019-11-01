Import-Module ActiveDirectory
$csv = Import-Csv -Path '.\password history demo example.csv'

foreach ($user_info in $csv){
  $Name = $user_info.Username
  $Passwords = @($user_info.'History 3',$user_info.'History 2',$user_info.'History 1',$user_info.'History 0', $user_info.'Current Password')
  $password = $user_info.'History 4'
  New-ADUser -Name $Name -SamAccountName $Name -AccountPassword(ConvertTo-SecureString -AsPlainText "$password" -Force) -Enabled $true
  foreach ($password in $Passwords) {
    Set-ADAccountPassword -Identity $Name -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$password" -Force)
  }
}