<?php
namespace SPHERE\Application\Setting\Authorization\Account;

use SPHERE\Application\Contact\Mail\Mail;
use SPHERE\Application\People\Person\Person;
use SPHERE\Application\Platform\Gatekeeper\Authentication\TwoFactorApp\TwoFactorApp;
use SPHERE\Application\Platform\Gatekeeper\Authorization\Access\Access;
use SPHERE\Application\Platform\Gatekeeper\Authorization\Access\Access as GatekeeperAccess;
use SPHERE\Application\Platform\Gatekeeper\Authorization\Access\Service\Entity\TblRole;
use SPHERE\Application\Platform\Gatekeeper\Authorization\Account\Account as GatekeeperAccount;
use SPHERE\Application\Platform\Gatekeeper\Authorization\Account\Service\Entity\TblAccount;
use SPHERE\Application\Platform\Gatekeeper\Authorization\Account\Service\Entity\TblIdentification;
use SPHERE\Application\Platform\Gatekeeper\Authorization\Consumer\Consumer as GatekeeperConsumer;
use SPHERE\Application\Platform\Gatekeeper\Authorization\Token\Token as GatekeeperToken;
use SPHERE\Application\Setting\Authorization\GroupRole\GroupRole;
use SPHERE\Common\Frontend\Form\IFormInterface;
use SPHERE\Common\Frontend\Form\Repository\Field\CheckBox;
use SPHERE\Common\Frontend\Form\Structure\FormColumn;
use SPHERE\Common\Frontend\Form\Structure\FormGroup;
use SPHERE\Common\Frontend\Form\Structure\FormRow;
use SPHERE\Common\Frontend\Icon\Repository\Info;
use SPHERE\Common\Frontend\Layout\Repository\PullClear;
use SPHERE\Common\Frontend\Layout\Repository\PullRight;
use SPHERE\Common\Frontend\Icon\Repository\Nameplate;
use SPHERE\Common\Frontend\Icon\Repository\Publicly;
use SPHERE\Common\Frontend\Icon\Repository\YubiKey;
use SPHERE\Common\Frontend\Layout\Repository\Title;
use SPHERE\Common\Frontend\Layout\Structure\Layout;
use SPHERE\Common\Frontend\Layout\Structure\LayoutColumn;
use SPHERE\Common\Frontend\Layout\Structure\LayoutGroup;
use SPHERE\Common\Frontend\Layout\Structure\LayoutRow;
use SPHERE\Common\Frontend\Link\Repository\ToggleSelective;
use SPHERE\Common\Frontend\Message\Repository\Danger;
use SPHERE\Common\Frontend\Message\Repository\Success;
use SPHERE\Common\Frontend\Text\Repository\ToolTip;
use SPHERE\Common\Window\Redirect;
use SPHERE\Common\Window\Stage;
use SPHERE\System\Extension\Repository\Sorter\StringGermanOrderSorter;

/**
 * Class Service
 *
 * @package SPHERE\Application\Setting\Authorization\Account
 */
class Service extends \SPHERE\Application\Platform\Gatekeeper\Authorization\Account\Service
{
    const MINIMAL_PASSWORD_LENGTH = 8;
    const MINIMAL_USERNAME_LENGTH = 3;

    /**
     * @param IFormInterface $Form
     * @param array          $Account
     *
     * @return IFormInterface|string
     */
    public function createAccount(IFormInterface $Form, $Account)
    {

        if (null === $Account) {

            return $Form;
        }

        $Error = false;

        $Username = trim($Account['Name']);
        $Password = trim($Account['Password']);
        $PasswordSafety = trim($Account['PasswordSafety']);

        $tblConsumer = GatekeeperConsumer::useService()->getConsumerBySession();

        $isAuthenticatorApp = false;
        $tblToken = false;
        if (isset($Account['Token'])) {
            if ((int)$Account['Token'] == -1) {
                $isAuthenticatorApp = true;
            } else {
                $tblToken = GatekeeperToken::useService()->getTokenById((int)$Account['Token']);
            }
        }

        if (empty( $Username )) {
            $Form->setError('Account[Name]', 'Bitte geben Sie einen Benutzernamen an');
            $Error = true;
        } else {
            if (preg_match('!^[a-z0-9]{'.self::MINIMAL_USERNAME_LENGTH.',}$!is', $Username)) {
                $Username = $tblConsumer->getAcronym().'-'.$Username;
                if (!GatekeeperAccount::useService()->getAccountByUsername($Username)) {
                    $Form->setSuccess('Account[Name]', '');
                } else {
                    $Form->setError('Account[Name]', 'Der angegebene Benutzername ist bereits vergeben');
                    $Error = true;
                }
            } else {
                $Form->setError('Account[Name]',
                    'Der Benutzername darf nur Buchstaben und Zahlen enthalten und muss mindestens
                    '.self::MINIMAL_USERNAME_LENGTH.' Zeichen lang sein. Es sind keine Umlaute oder Sonderzeichen erlaubt.');
                $Error = true;
            }
        }

        if (empty( $Password )) {
            $Form->setError('Account[Password]', 'Bitte geben Sie ein Passwort an');
            $Error = true;
        } else {
            if (strlen($Password) >= self::MINIMAL_PASSWORD_LENGTH) {
                $Form->setSuccess('Account[Password]', '');
            } else {
                $Form->setError('Account[Password]', 'Das Passwort muss mindestens '.self::MINIMAL_PASSWORD_LENGTH.' Zeichen lang sein');
                $Error = true;
            }
        }

        if (empty( $PasswordSafety )) {
            $Form->setError('Account[PasswordSafety]', 'Bitte geben Sie das Passwort erneut an');
            $Error = true;
        }
        if ($Password != $PasswordSafety) {
            $Form->setError('Account[Password]', '');
            $Form->setError('Account[PasswordSafety]', 'Die beiden Passworte stimmen nicht überein');
            $Error = true;
        } else {
            if (!empty( $Password ) && !empty( $PasswordSafety )) {
                $Form->setSuccess('Account[PasswordSafety]', '');
            } else {
                $Form->setError('Account[PasswordSafety]', '');
            }
        }

        if (!isset( $Account['User'] )) {
            $Form->prependGridGroup(
                new FormGroup(new FormRow(new FormColumn(new Danger('Bitte wählen Sie einen Besitzer des Kontos aus (Person wählen)'))))
            );
            $Error = true;
        }

        if (!$Error) {
            if (isset($Account['User'])) {
                $tblPerson = Person::useService()->getPersonById($Account['User']);
            } else {
                $tblPerson = false;
            }

            //  für Mitarbeiter den AccountAlias aus E-Mails setzen
            if ($tblPerson) {
                if (($accountUserAlias = GatekeeperAccount::useService()->getAccountUserAliasFromMails($tblPerson))) {
                    $errorMessage = '';
                    if (!GatekeeperAccount::useService()->isUserAliasUnique($tblPerson, $accountUserAlias,
                        $errorMessage)
                    ) {
                        $accountUserAlias = false;
                        // Flag an der E-Mail Adresse entfernen
                        Mail::useService()->resetMailWithUserAlias($tblPerson);
                    }
                }
                $accountRecoveryMail = GatekeeperAccount::useService()->getAccountRecoveryMailFromMails($tblPerson);
            } else {
                $accountUserAlias = false;
                $accountRecoveryMail = false;
            }

            $tblAccount = GatekeeperAccount::useService()->insertAccount(
                $Username,
                $Password,
                $tblToken ? $tblToken : null,
                $tblConsumer,
                true,
                $isAuthenticatorApp,
                $accountUserAlias ? $accountUserAlias : null,
                $accountRecoveryMail ? $accountRecoveryMail : null
            );
            if ($tblAccount) {
                if ($isAuthenticatorApp) {
                    $tblIdentification = GatekeeperAccount::useService()->getIdentificationByName(TblIdentification::NAME_AUTHENTICATOR_APP);
                } elseif($tblToken) {
                    // Nutzerkonten ohne Hardware-Schlüssel können sich nicht mehr einlogen
                    $tblIdentification = GatekeeperAccount::useService()->getIdentificationByName(TblIdentification::NAME_TOKEN);
                } else {
                    $tblIdentification = GatekeeperAccount::useService()->getIdentificationByName(TblIdentification::NAME_CREDENTIAL);
                }
                GatekeeperAccount::useService()->addAccountAuthentication($tblAccount, $tblIdentification);
                if (isset( $Account['Role'] )) {
                    foreach ((array)$Account['Role'] as $Role) {
                        $tblRole = GatekeeperAccess::useService()->getRoleById($Role);
                        if(
                            $tblIdentification->getName() == TblIdentification::NAME_CREDENTIAL
                            && !$tblRole->isSecure()
                        ) {
                            GatekeeperAccount::useService()->addAccountAuthorization($tblAccount, $tblRole);
                        } else if (
                            !$tblRole->isSecure()
                            || (
                                $tblIdentification->getName() != TblIdentification::NAME_CREDENTIAL
                                && ($tblToken || $isAuthenticatorApp)
                            )
                        ) {
                            GatekeeperAccount::useService()->addAccountAuthorization($tblAccount, $tblRole);
                        }
                    }
                }
                if ($tblPerson) {
                    GatekeeperAccount::useService()->addAccountPerson($tblAccount, $tblPerson);
                }

                return new Success('Das Benutzerkonto wurde erstellt')
                .new Redirect('/Setting/Authorization/Account', Redirect::TIMEOUT_SUCCESS);
            } else {
                return new Danger('Das Benutzerkonto konnte nicht erstellt werden')
                .new Redirect('/Setting/Authorization/Account', Redirect::TIMEOUT_ERROR);
            }
        }

        return $Form;
    }

    /**
     * @param IFormInterface $Form
     * @param TblAccount     $tblAccount
     * @param array          $Account
     *
     * @return IFormInterface|string
     */
    public function changeAccountForm(IFormInterface $Form, TblAccount $tblAccount, $Account)
    {

        if (null === $Account) {

            return $Form;
        }

        $Error = false;

        $Password = trim($Account['Password']);
        $PasswordSafety = trim($Account['PasswordSafety']);

        $isAuthenticatorApp = false;
        $tblToken = false;
        if (isset($Account['Token'])) {
            if ((int)$Account['Token'] == -1) {
                $isAuthenticatorApp = true;
            } else {
                $tblToken = GatekeeperToken::useService()->getTokenById((int)$Account['Token']);
            }
        }

        if (!empty( $Password )) {
            if (strlen($Password) >= self::MINIMAL_PASSWORD_LENGTH) {
                $Form->setSuccess('Account[Password]', '');
            } else {
                $Form->setError('Account[Password]', 'Das Passwort muss mindestens '.self::MINIMAL_PASSWORD_LENGTH.' Zeichen lang sein');
                $Error = true;
            }
        }
        if (!empty( $Password ) && empty( $PasswordSafety )) {
            $Form->setError('Account[PasswordSafety]', 'Bitte geben Sie das Passwort erneut an');
            $Error = true;
        }
        if (!empty( $Password ) && $Password != $PasswordSafety) {
            $Form->setError('Account[Password]', '');
            $Form->setError('Account[PasswordSafety]', 'Die beiden Passworte stimmen nicht überein');
            $Error = true;
        }

        if (!$Error) {
            if ($tblAccount) {
                $tblIdentification = $tblAccount->getServiceTblIdentification();

                // entfernen aller Rechte bei Update auf "KEIN Hardware-Schlüssel notwendig"
                if($tblAccount->getServiceTblToken()
                    || $tblIdentification->getName() == TblIdentification::NAME_AUTHENTICATOR_APP
                    || $tblIdentification->getName() == TblIdentification::NAME_TOKEN){
                    if($Account['Token'] === '0'){
                        return Account::useFrontend()->frontendConfirmChange($tblAccount->getId(), $Account);
                    }
                }

                // Edit Token
                GatekeeperAccount::useService()->changeToken($tblToken ? $tblToken : null, $tblAccount);

                if($isAuthenticatorApp){
                    $tblIdentificationChoose = GatekeeperAccount::useService()->getIdentificationByName(TblIdentification::NAME_AUTHENTICATOR_APP);
                } elseif($tblToken){
                    $tblIdentificationChoose = GatekeeperAccount::useService()->getIdentificationByName(TblIdentification::NAME_TOKEN);
                } else {
                    $tblIdentificationChoose = GatekeeperAccount::useService()->getIdentificationByName(TblIdentification::NAME_CREDENTIAL);
                }

                // set Token
                if ($tblToken && $tblIdentification->getId() != $tblIdentificationChoose->getId()) {
                    GatekeeperAccount::useService()->removeAccountAuthentication($tblAccount, $tblIdentification);
                    GatekeeperAccount::useService()->addAccountAuthentication($tblAccount, $tblIdentificationChoose);
                // set Authenticator App
                } elseif ($isAuthenticatorApp && $tblIdentification->getId() != $tblIdentificationChoose->getId()) {
                    GatekeeperAccount::useService()->removeAccountAuthentication($tblAccount, $tblIdentification);
                    GatekeeperAccount::useService()->addAccountAuthentication($tblAccount, $tblIdentificationChoose);
                    if (!$tblAccount->getAuthenticatorAppSecret()) {
                        $twoFactorApp = new TwoFactorApp();
                        GatekeeperAccount::useService()->changeAuthenticatorAppSecret($tblAccount, $twoFactorApp->createSecret());
                    }
                // set Credential
                } elseif($tblIdentification->getId() != $tblIdentificationChoose->getId()) {
                    GatekeeperAccount::useService()->removeAccountAuthentication($tblAccount, $tblIdentification);
                    GatekeeperAccount::useService()->addAccountAuthentication($tblAccount, $tblIdentificationChoose);
                }
                $tblIdentification = $tblIdentificationChoose;

                // Edit Access
                $tblAccessList = GatekeeperAccount::useService()->getAuthorizationAllByAccount($tblAccount);
                if ($tblAccessList) {
                    foreach ($tblAccessList as $tblAccessRemove) {
                        GatekeeperAccount::useService()->removeAccountAuthorization($tblAccount,
                            $tblAccessRemove->getServiceTblRole());
                    }
                }
                if (isset( $Account['Role'] )) {
                    foreach ((array)$Account['Role'] as $Role) {
                        $tblRole = GatekeeperAccess::useService()->getRoleById($Role);
                        if(
                            $tblIdentification->getName() == TblIdentification::NAME_CREDENTIAL
                            && !$tblRole->isSecure()
                        ) {
                            GatekeeperAccount::useService()->addAccountAuthorization($tblAccount, $tblRole);
                        } else if (
                            !$tblRole->isSecure()
                            || (
                                $tblIdentification->getName() != TblIdentification::NAME_CREDENTIAL
                                && ($tblToken || $isAuthenticatorApp)
                            )
                        ) {
                            GatekeeperAccount::useService()->addAccountAuthorization($tblAccount, $tblRole);
                        }
                    }
                }

                // Edit Password
                if (!empty( $Password )) {
                    GatekeeperAccount::useService()->changePassword($Password, $tblAccount);
                }

                return new Success('Das Benutzerkonto wurde geändert')
                .new Redirect('/Setting/Authorization/Account', Redirect::TIMEOUT_SUCCESS);
            } else {
                return new Danger('Das Benutzerkonto konnte nicht geändert werden')
                .new Redirect('/Setting/Authorization/Account', Redirect::TIMEOUT_ERROR);
            }
        }

        return $Form;
    }

    /**
     * @param int   $tblAccountId
     * @param array $Account
     *
     * @return IFormInterface|string
     */
    public function changeAccount($tblAccountId, $Account)
    {

        $Stage = new Stage('Benutzerkonto', 'Bearbeiten');

        $tblAccount = Account::useService()->getAccountById($tblAccountId);
        $tblIdentification = $tblAccount->getServiceTblIdentification();
        $tblIdentificationChoose = GatekeeperAccount::useService()->getIdentificationByName(TblIdentification::NAME_CREDENTIAL);
        // set Credential
        if($tblIdentification->getId() != $tblIdentificationChoose->getId()) {
            GatekeeperAccount::useService()->removeAccountAuthentication($tblAccount, $tblIdentification);
            GatekeeperAccount::useService()->addAccountAuthentication($tblAccount, $tblIdentificationChoose);
        }
        // Edit Token
        GatekeeperAccount::useService()->changeToken(null, $tblAccount);

        // Edit Access
        $tblAccessList = GatekeeperAccount::useService()->getAuthorizationAllByAccount($tblAccount);
        if ($tblAccessList) {
            foreach ($tblAccessList as $tblAccessRemove) {
                GatekeeperAccount::useService()->removeAccountAuthorization($tblAccount,
                    $tblAccessRemove->getServiceTblRole());
            }
        }

        $Password = trim($Account['Password']);
        // Edit Password
        if (!empty($Password)) {
            GatekeeperAccount::useService()->changePassword($Password, $tblAccount);
        }

        return $Stage->setContent(new Success('Das Benutzerkonto wurde geändert')
            .new Redirect('/Setting/Authorization/Account', Redirect::TIMEOUT_SUCCESS));
    }

    /**
     * @param string $dataName
     *
     * @return array|bool|TblRole[]
     */
    public function getRoleCheckBoxList($dataName = 'Account[Role]')
    {
        // Role
        $tblRoleAll = Access::useService()->getRolesForSelect(true);
        $tblRoleAll = $this->getSorter($tblRoleAll)->sortObjectBy(TblRole::ATTR_NAME, new StringGermanOrderSorter());
        if ($tblRoleAll){
            array_walk($tblRoleAll, function(TblRole &$tblRole) use(&$TeacherRole, $dataName){

                $tblRole = new Layout(new LayoutGroup(new LayoutRow(array(
                    new LayoutColumn(
                        new CheckBox($dataName . '['.$tblRole->getId().']', ($tblRole->isSecure() ? new YubiKey() : new Publicly()).' '.$tblRole->getName(), $tblRole->getId())
                        , 8),

                    new LayoutColumn(
                        new PullRight((Account::useService()->getRoleDescriptionToolTipByRole($tblRole)))
                        , 4)
                ))));

            //    $tblRole = new PullClear($checkBox.new PullRight(Account::useService()->getRoleDescriptionToolTipByRole($tblRole)));
            });
            $tblRoleAll = array_filter($tblRoleAll);
        } else {
            $tblRoleAll = array();
        }

        return $tblRoleAll;
    }

    /**
     * @return LayoutGroup
     */
    public function getGroupRoleLayoutGroup()
    {
        $toggleButtons = array();

        // alle ab/anwählen
        if (($tblRoleAll = Access::useService()->getRolesForSelect(true))) {
            $toggles = array();
            foreach ($tblRoleAll as $item) {
                $toggles[] = 'Account[Role][' . $item->getId() . ']';
            }

            $toggleButtons[] = new ToggleSelective('Alle Benutzerechte wählen/abwählen', $toggles);
        }

        if (($tblGroupRoleList = GroupRole::useService()->getGroupRoleAll())) {
            foreach ($tblGroupRoleList as $tblGroupRole) {
                if (($tblGroupRoleLinkList = GroupRole::useService()->getGroupRoleLinkAllByGroupRole($tblGroupRole))) {
                    $toggles = array();
                    foreach ($tblGroupRoleLinkList as $tblGroupRoleLink) {
                        if (($tblRole = $tblGroupRoleLink->getServiceTblRole())) {
                            $toggles[] = 'Account[Role][' . $tblRole->getId() . ']';
                        }
                    }
                    $toggleButtons[] = new ToggleSelective($tblGroupRole->getName(), $toggles);
                }
            }
        }

        return new LayoutGroup(new LayoutRow(new LayoutColumn(implode(' ' , $toggleButtons))), new Title(new Nameplate() . ' Benutzerrolle'));
    }

    /**
     * @return false|TblAccount[]
     */
    public function getAccountAllForEdit()
    {
        $tblIdentificationToken = Account::useService()->getIdentificationByName(TblIdentification::NAME_TOKEN);
        $tblAccountConsumerTokenList = array();
        if($tblIdentificationToken){
            $tblAccountConsumerTokenList = Account::useService()->getAccountListByIdentification($tblIdentificationToken);
            if(!$tblAccountConsumerTokenList){
                $tblAccountConsumerTokenList = array();
            }
        }
        if (($tblIdentificationAuthenticatorApp = Account::useService()->getIdentificationByName(TblIdentification::NAME_AUTHENTICATOR_APP))
            && ($tblAccountConsumerAuthenticatorAppList = Account::useService()->getAccountListByIdentification($tblIdentificationAuthenticatorApp))
        ) {
            if (!empty($tblAccountConsumerTokenList)) {
                $tblAccountConsumerTokenList = array_merge($tblAccountConsumerTokenList, $tblAccountConsumerAuthenticatorAppList);
            } else {
                $tblAccountConsumerTokenList = $tblAccountConsumerAuthenticatorAppList;
            }
        }
        if (($tblIdentificationCredential = Account::useService()->getIdentificationByName(TblIdentification::NAME_CREDENTIAL))
            && ($tblAccountConsumerCredentialList = Account::useService()->getAccountListByIdentification($tblIdentificationCredential))
        ) {
            if (!empty($tblAccountConsumerTokenList)) {
                $tblAccountConsumerTokenList = array_merge($tblAccountConsumerTokenList, $tblAccountConsumerCredentialList);
            } else {
                $tblAccountConsumerTokenList = $tblAccountConsumerCredentialList;
            }
        }

        return empty($tblAccountConsumerTokenList) ? false : $tblAccountConsumerTokenList;
    }

    public function getRoleDescriptionToolTipByRole(TblRole $tblRole) {

        switch ($tblRole->getName()) {
            case 'Auswertung: Allgemein': return new ToolTip(new Info(), 'Auswertungen (Standard, Individual), Check-Listen, Adresslisten für Serienbriefe');
            case 'Auswertung: Flexible Auswertung': return new ToolTip(new Info(), 'Flexible Auswertung (Auswertungen selbst zusammenstellen)');
            case 'Auswertung: Kamenz-Statistik': return new ToolTip(new Info(), 'Auswertungen für die Kamenz-Statistik (verfügbar für Schulträger, die die anteilige Kostenübernahme für diese Auswertung über die Schulstiftung explizit zugesagt haben)');
            case 'Bildung: Fehlzeiten (Verwaltung)': return new ToolTip(new Info(), 'Fehlzeitenverwaltung Kalenderansicht mit direkter Suche über alle Schüler');
            case 'Bildung: Klassenbuch (Lehrer mit Lehrauftrag)': return new ToolTip(new Info(), 'Digitales Klassenbuch für Lehrer mit Lehrauftrag und Klassenlehrer');
            case 'Bildung: Klassenbuch (Alle Klassenbücher)': return new ToolTip(new Info(), 'Digitales Klassenbuch aller Klassen');
            case 'Bildung: Klassenbuch (Integrationsbeauftragte)': return new ToolTip(new Info(), 'Digitales Klassenbuch und Integration aller Klassen');
            case 'Bildung: Klassenbuch (Schulleitung)': return new ToolTip(new Info(), 'Digitales Klassenbuch, Integration und inkl. Verwaltung und Auswertung von Belehrungen aller Klassen');
            case 'Bildung: Notenbuch (Integrationsbeauftragte)': return new ToolTip(new Info(), 'Notenbuch aller Schüler');
            case 'Bildung: pädagogisches Tagebuch (Klassenlehrer)': return new ToolTip(new Info(), 'pädagogisches Tagebuch (Klassenlehrer mit eigener Klasse)');
            case 'Bildung: pädagogisches Tagebuch (Schulleitung)': return new ToolTip(new Info(), 'pädagogisches Tagebuch (alle Klassen)');
            case 'Bildung: Unterrichtsverwaltung': return new ToolTip(new Info(), 'Fächer-, Schuljahr- und Klassenverwaltung, Sortierung aller Klassen');
            case 'Schüler und Eltern Zugang': return new ToolTip(new Info(), 'Zensurenübersicht, Online Krankmeldung und Online Kontakten Änderungswünsche für Eltern/Schüler (wird bei Generierung der Schüler/Eltern - Zugänge automatisch gesetzt), auch notwendig für Mitarbeiter, welche gleichzeitig Eltern sind');
            case 'Bildung: Zensurenvergabe (Lehrer)': return new ToolTip(new Info(), 'Notenvergabe, Notenbuch für Lehrer mit Lehrauftrag, Notenbuch, Schülerübersicht, Einsicht Notenaufträge für Klassenlehrer (eigene Klasse)');
            case 'Bildung: Zensurenvergabe (Schulleitung)': return new ToolTip(new Info(), 'Notenvergabe, Notenbuch in allen Klassen, Festlegung und Einsicht Notenaufträge (Stichtags- und Kopfnoten');
            case 'Bildung: Zensurenverwaltung': return new ToolTip(new Info(), 'Festlegung von Zensuren-Typen, Berechnungsvorschriften, Bewertungssystemen, Mindestnotenanzahl');
            case 'Bildung: Zeugnis (Drucken - Klassenlehrer)': return new ToolTip(new Info(), 'Drucken der Zeugnisse für Klassenlehrer (automatische Eingrenzung auf die jeweilige Klasse)');
            case 'Bildung: Zeugnis (Drucken)': return new ToolTip(new Info(), 'Drucken der Zeugnisse');
            case 'Bildung: Zeugnis (Einstellungen)': return new ToolTip(new Info(), 'Einstellungen Zeugnisvorlagen (Fächer und deren Reihenfolge auf den Zeugnis');
            case 'Bildung: Zeugnis (Freigabe)': return new ToolTip(new Info(), 'Freitgabe der Zeugnisse für den Druck');
            case 'Bildung: Zeugnis (Generierung)': return new ToolTip(new Info(), 'Generierung eines Zeugnisauftrages (Zeugnisdatum und -vorlage, Stichtags- und Kopfnotenauftrag, Name Schulleiter/in');
            case 'Bildung: Zeugnis (Vorbereitung - Abgangszeugnisse)': return new ToolTip(new Info(), 'Zeugnisvorbereitung der Abgangszeugnisse für Oberschule und Gymnasium (SEKI)');
            case 'Bildung: Zeugnis (Vorbereitung - Abschlusszeugnisse)': return new ToolTip(new Info(), 'Zeugnisvorbereitung der Abschlusszeugnisse (Prüfungsnoten, Vorjahresnoten, etc.)');
            case 'Bildung: Zeugnis (Vorbereitung - Klassenlehrer)': return new ToolTip(new Info(), 'Zeugnisvorbereitung (Festlegung Kopfnoten, Hinterlegung sonstiger Informationen wie Bemerkung, Fehlzeiten etc.)');
            case 'Datentransfer: Import und Export': return new ToolTip(new Info(), 'Import der Lehraufträge aus externer Stundenplansoftware');
            case 'Dokumente': return new ToolTip(new Info(), 'Dokumentendruck Standard (Schulbescheinigung, Schülerkartei) und Individual');
            case 'Einstellungen: Administrator': return new ToolTip(new Info(), 'Verwaltung von Benutzerkonten, Mandanteinstellungen, Eigenes Passwort ändern');
            case 'Einstellungen: Benutzer': return new ToolTip(new Info(), 'Benutzereinestellungen (Aussehen der Programmoberfläche, Eigenes Passwort änden, Hilfe und Support)');
            case 'Einstellungen: Benutzer (Schüler/Eltern) - nicht sichtbar': return new ToolTip(new Info(), 'Benutzereinestellungen (Aussehen der Programmoberfläche, Eigenes Passwort änden, wird bei Generierung der Schüler/Eltern - Zugänge automatisch gesetzt)');
            case 'Einstellungen: Verwaltung Schüler und Eltern Zugang': return new ToolTip(new Info(), 'Erstellung der Benutzerkontos für Eltern / Schüler inkl. Passwortrücksetzung');
            case 'Fakturierung': return new ToolTip(new Info(), 'Fakturierungsmodul (z.B. Verwaltung von Schulgeld');
            case 'Feedback & Support': return new ToolTip(new Info(), 'Supportformular Ticketsystem');
            case 'Stammdaten: Institutionenverwaltung (Lesen + Schreiben)': return new ToolTip(new Info(), 'Verwaltung von Institutionen (Schulen, Kitas, etc.)');
            case 'Stammdaten: Institutionenverwaltung (Lesen)': return new ToolTip(new Info(), 'ReadOnly von Institutionen (Schulen, Kitas etc.)');
            case 'Stammdaten: Personenverwaltung (Lesen + Schreiben)': return new ToolTip(new Info(), 'Verwaltung von Personen (Schüler, Sorgeberechtigte Interessenten, Lehrer, etc.');
            case 'Stammdaten: Personenverwaltung (Lesen)': return new ToolTip(new Info(), 'ReadOnly von Personen (Schüler, Sorgeberechtigte, Interessenten, Lehrer, etc.');
        }
        return '';

    }
}
