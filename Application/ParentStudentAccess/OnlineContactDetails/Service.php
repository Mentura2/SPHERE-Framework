<?php

namespace SPHERE\Application\ParentStudentAccess\OnlineContactDetails;

use DateTime;
use SPHERE\Application\Contact\Phone\Phone;
use SPHERE\Application\ParentStudentAccess\OnlineContactDetails\Service\Data;
use SPHERE\Application\ParentStudentAccess\OnlineContactDetails\Service\Entity\TblOnlineContact;
use SPHERE\Application\ParentStudentAccess\OnlineContactDetails\Service\Setup;
use SPHERE\Application\People\Meta\Student\Student;
use SPHERE\Application\People\Person\Person;
use SPHERE\Application\People\Person\Service\Entity\TblPerson;
use SPHERE\Application\People\Relationship\Relationship;
use SPHERE\Application\Platform\Gatekeeper\Authorization\Account\Account;
use SPHERE\Application\Setting\Consumer\Consumer;
use SPHERE\Common\Frontend\Form\Structure\Form;
use SPHERE\Common\Frontend\Layout\Repository\Container;
use SPHERE\System\Database\Binding\AbstractService;
use SPHERE\System\Database\Fitting\Element;

class Service extends AbstractService
{
    /**
     * @param bool $doSimulation
     * @param bool $withData
     * @param bool $UTF8
     *
     * @return string
     */
    public function setupService($doSimulation, $withData, $UTF8): string
    {
        $Protocol= '';
        if(!$withData){
            $Protocol = (new Setup($this->getStructure()))->setupDatabaseSchema($doSimulation, $UTF8);
        }
        if (!$doSimulation && $withData) {
            (new Data($this->getBinding()))->setupDatabaseContent();
        }

        return $Protocol;
    }

    /**
     * eingeloggte Person ist ein Schüler -> nur ab 18 Jahre
     *
     * @return array|false
     */
    public function getPersonListFromStudentLogin()
    {
        $tblPersonList = array();
        if (($tblPerson = Account::useService()->getPersonByLogin())
            && ($tblSetting = Consumer::useService()->getSetting('ParentStudentAccess', 'Person', 'ContactDetails', 'OnlineContactDetailsAllowedForSchoolTypes'))
            && ($tblSchoolTypeAllowedList = Consumer::useService()->getSchoolTypeBySettingString($tblSetting->getValue()))
        ) {
            if (($tblDivision = Student::useService()->getCurrentMainDivisionByPerson($tblPerson))
                && ($tblType = $tblDivision->getType())
                && isset($tblSchoolTypeAllowedList[$tblType->getId()])
                && ($birthday = $tblPerson->getBirthday())
                && (new DateTime($birthday)) <= ((new DateTime('now'))->modify('-18 year'))
            ) {
                $tblPersonList[$tblPerson->getId()] = $tblPerson;

                // und anzeige der Sorgeberechtigt, Bevollmächtigt, Vormund -> erstmal nicht
//                if (($tblPersonRelationshipList = Relationship::useService()->getPersonRelationshipAllByPerson($tblPerson))) {
//                    foreach ($tblPersonRelationshipList as $relationship) {
//                        if (($tblPersonFrom = $relationship->getServiceTblPersonFrom())
//                            && $tblPersonFrom->getId() != $tblPerson->getId()
//                            && ($relationship->getTblType()->getName() == 'Sorgeberechtigt'
//                                || $relationship->getTblType()->getName() == 'Bevollmächtigt'
//                                || $relationship->getTblType()->getName() == 'Vormund')
//                        ) {
//                            $tblPersonList[$tblPersonFrom->getId()] = $tblPersonFrom;
//                        }
//                    }
//                }
            }
        }

        return empty($tblPersonList) ? false : $tblPersonList;
    }

    /**
     * nur eingeloggter Elternteil + Kinder, erstmal nicht die weiteren Elternteile aus Datenschutzgründen
     *
     * @return array|false
     */
    public function getPersonListFromCustodyLogin()
    {
        $tblPersonList = array();
        if (($tblPerson = Account::useService()->getPersonByLogin())
            && ($tblSetting = Consumer::useService()->getSetting('ParentStudentAccess', 'Person', 'ContactDetails', 'OnlineContactDetailsAllowedForSchoolTypes'))
            && ($tblSchoolTypeAllowedList = Consumer::useService()->getSchoolTypeBySettingString($tblSetting->getValue()))
        ) {
            // Kinder des Elternteils
            if (($tblPersonRelationshipList = Relationship::useService()->getPersonRelationshipAllByPerson($tblPerson))) {
                foreach ($tblPersonRelationshipList as $relationship) {
                    if (($tblPersonTo = $relationship->getServiceTblPersonTo())
                        && $tblPersonTo->getId() != $tblPerson->getId()
                        && ($relationship->getTblType()->getName() == 'Sorgeberechtigt'
                            || $relationship->getTblType()->getName() == 'Bevollmächtigt'
                            || $relationship->getTblType()->getName() == 'Vormund')
                    ) {
                        // prüfen: ob die Schulart freigeben ist
                        if (($tblDivision = Student::useService()->getCurrentMainDivisionByPerson($tblPersonTo))
                            && ($tblType = $tblDivision->getType())
                            && isset($tblSchoolTypeAllowedList[$tblType->getId()])
                        ) {
                            $tblPersonList[$tblPersonTo->getId()] = $tblPersonTo;
                        }
                    }
                }
            }

            // eingeloggter Elternteil
            if ($tblPersonList) {
                $tblPersonList[$tblPerson->getId()] = $tblPerson;
            }
        }

        return empty($tblPersonList) ? false : $tblPersonList;
    }

    /**
     * @param array $tblPersonList
     *
     * @return array
     */
    public function getPersonIdListFromPersonList(array $tblPersonList): array
    {
        $personIdList = array();
        foreach ($tblPersonList as $tblPerson) {
            $personIdList[$tblPerson->getId()] = $tblPerson->getId();
        }

        return $personIdList;
    }

    /**
     * @param $tblPersonList
     * @param $filterPersonIdList
     *
     * @return array
     */
    public function getPersonListWithFilter($tblPersonList, $filterPersonIdList): array
    {
        $result = array();
        if ($tblPersonList) {
            foreach ($tblPersonList as $tblPerson) {
                if (isset($filterPersonIdList[$tblPerson->getId()])) {
                    $result[$tblPerson->getId()] = $tblPerson->getId();
                }
            }
        }

        return $result;
    }

    /**
     * @param array|false $personIdList
     *
     * @return string
     */
    public function getNameStringFromPersonIdList($personIdList): string
    {
        $result = array();
        if ($personIdList) {
            foreach ($personIdList as $personId) {
                if ($tblPerson = Person::useService()->getPersonById($personId)) {
                    $result[$personId] = $tblPerson->getFullName();
                }
            }
        }

        return empty($result) ? '' : implode(', ', $result) ;
    }

    /**
     * @param string $ContactType
     * @param Element $tblToPerson
     *
     * @return false|TblOnlineContact[]
     */
    public function getOnlineContactAllByToPerson(string $ContactType, Element $tblToPerson)
    {
        return (new Data($this->getBinding()))->getOnlineContactAllByToPerson($ContactType, $tblToPerson);
    }

    /**
     * @param string $ContactType
     * @param Element $tblToPerson
     *
     * @return string
     */
    public function getOnlineContactStringByToPerson(string $ContactType, Element $tblToPerson): string
    {
        $list = array();
        if (($tblOnlineContactDetailList = $this->getOnlineContactAllByToPerson($ContactType, $tblToPerson))) {
            foreach ($tblOnlineContactDetailList as $tblOnlineContact) {
                $list[] = new Container($tblOnlineContact->getContactString());
            }
        }

        return empty($list) ? '' : implode(' ', $list);
    }

    /**
     * @param TblPerson $tblPerson
     * @param $PhoneId
     * @param array $PersonIdList
     * @param array $Data
     *
     * @return false|Form
     */
    public function checkFormPhone(
        TblPerson $tblPerson,
        $PhoneId,
        array $PersonIdList,
        array $Data
    ) {
        $error = false;
        $form = OnlineContactDetails::useFrontend()->formPhone($tblPerson->getId(), $PhoneId, $PersonIdList);
        if (isset($Data['Number']) && empty($Data['Number'])) {
            $form->setError('Data[Number]', 'Bitte geben Sie eine gültige Telefonnummer an');
            $error = true;
        } else {
            $form->setSuccess('Number');
        }

        return $error ? $form : false;
    }

    /**
     * @param TblPerson $tblPerson
     * @param $ToPersonId
     * @param array $Data
     *
     * @return bool
     */
    public function createPhone(
        TblPerson $tblPerson,
        $ToPersonId,
        array $Data
    ): bool {

        if (($tblPhone = Phone::useService()->insertPhone($Data['Number']))
            && ($tblPersonLogin = Account::useService()->getPersonByLogin())
        ) {
            $tblToPerson = $ToPersonId ? Phone::useService()->getPhoneToPersonById($ToPersonId) : null;

            (new Data($this->getBinding()))->createOnlineContact(TblOnlineContact::VALUE_TYPE_PHONE, $tblToPerson ?: null, $tblPhone, $tblPerson,
                $Data['Remark'], $tblPersonLogin);

            if (isset($Data['PersonList'])) {
                foreach ($Data['PersonList'] as $personId => $value) {
                    if ($tblPersonItem = Person::useService()->getPersonById($personId)) {
                        if ($tblToPerson)  {
                            $tblToPersonTemp = Phone::useService()->getPhoneToPersonByPersonAndPhone($tblPersonItem, $tblToPerson->getTblPhone());
                        } else {
                            $tblToPersonTemp = null;
                        }

                        (new Data($this->getBinding()))->createOnlineContact(TblOnlineContact::VALUE_TYPE_PHONE, $tblToPersonTemp ?: null, $tblPhone, $tblPersonItem,
                            $Data['Remark'], $tblPersonLogin);
                    }
                }
            }

            return true;
        }

        return false;
    }
}