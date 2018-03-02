<?php

namespace SPHERE\Application\Reporting\Individual\Service\Entity;

use Doctrine\ORM\Mapping\Cache;
use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\Table;
use SPHERE\Application\Education\School\Course\Course;
use SPHERE\Application\Education\School\Course\Service\Entity\TblCourse;
use SPHERE\Common\Frontend\Form\Repository\AbstractField;
use SPHERE\Common\Frontend\Form\Repository\Field\NumberField;
use SPHERE\Common\Frontend\Icon\IIconInterface;
use SPHERE\Common\Frontend\Icon\Repository\Pencil;
use SPHERE\System\Database\Binding\AbstractService;
use SPHERE\System\Database\Binding\AbstractView;

/**
 * @Entity
 * @Table(name="viewStudent")
 * @Cache(usage="READ_ONLY")
 */
class ViewStudent extends AbstractView
{

    // Sortierung beeinflusst die Gruppenreihenfolge im Frontend
    const TBL_PERSON_ID = 'TblPerson_Id';

    const TBL_STUDENT_IDENTIFIER = 'TblStudent_Identifier';
    const SCHULE = 'Schule';
    const BILDUNGSGANG = 'Bildungsgang';
    const TBL_STUDENT_MEDICAL_RECORD_DISEASE = 'TblStudentMedicalRecord_Disease';
    const TBL_STUDENT_MEDICAL_RECORD_MEDICATION = 'TblStudentMedicalRecord_Medication';
//    const ARBEITSGEMEINSCHAFT_1 = 'Arbeitsgemeinschaft1';
//    const ARBEITSGEMEINSCHAFT_2 = 'Arbeitsgemeinschaft2';
//    const ARBEITSGEMEINSCHAFT_3 = 'Arbeitsgemeinschaft3';
    const FREMDSPRACHE_1 = 'Fremdsprache1';
    const FREMDSPRACHE_2 = 'Fremdsprache2';
    const FREMDSPRACHE_3 = 'Fremdsprache3';
    const FREMDSPRACHE_4 = 'Fremdsprache4';
//    const WAHLFACH_1 = 'Wahlfach1';
//    const WAHLFACH_2 = 'Wahlfach2';
//    const WAHLFACH_3 = 'Wahlfach3';
    const RELIGION = 'Religion';
    const PROFIL = 'Profil';
    const NEIGUNGSKURS = 'Neigungskurs';
//    const BEFREIUNGEN = 'Befreiungen';

    const TBL_STUDENT_MEDICAL_RECORD_INSURANCE = 'TblStudentMedicalRecord_Insurance';
    const TBL_STUDENT_LOCKER_KEY_NUMBER = 'TblStudentLocker_KeyNumber';
    const TBL_STUDENT_LOCKER_LOCKER_NUMBER = 'TblStudentLocker_LockerNumber';
    const SIBLINGS_COUNT = 'Sibling_Count';

    // S1
    const TBL_SALUTATION_SALUTATION_S1 = 'TblSalutation_Salutation_S1';
    const TBL_PERSON_TITLE_S1 = 'TblPerson_Title_S1';
    const TBL_PERSON_FIRST_NAME_S1 = 'TblPerson_FirstName_S1';
    const TBL_PERSON_SECOND_NAME_S1 = 'TblPerson_SecondName_S1';
    const TBL_PERSON_LAST_NAME_S1 = 'TblPerson_LastName_S1';
    const TBL_PERSON_BIRTH_NAME_S1 = 'TblPerson_BirthName_S1';
    const TBL_ADDRESS_STREET_NAME_S1 = 'TblAddress_StreetName_S1';
    const TBL_ADDRESS_STREET_NUMBER_S1 = 'TblAddress_StreetNumber_S1';
    const TBL_CITY_CODE_S1 = 'TblCity_Code_S1';
    const TBL_CITY_CITY_S1 = 'TblCity_City_S1';
    const TBL_CITY_DISTRICT_S1 = 'TblCity_District_S1';
    const TBL_ADDRESS_COUNTY_S1 = 'TblAddress_County_S1';
    const TBL_ADDRESS_STATE_S1 = 'TblState_Name_S1';
    const TBL_ADDRESS_NATION_S1 = 'TblAddress_Nation_S1';
    const TBL_PHONE_NUMBER_S1 = 'TblPhone_Number_S1';
    const TBL_MAIL_ADDRESS_S1 = 'TblMail_Address_S1';

    // S2
    const TBL_SALUTATION_SALUTATION_S2 = 'TblSalutation_Salutation_S2';
    const TBL_PERSON_TITLE_S2 = 'TblPerson_Title_S2';
    const TBL_PERSON_FIRST_NAME_S2 = 'TblPerson_FirstName_S2';
    const TBL_PERSON_SECOND_NAME_S2 = 'TblPerson_SecondName_S2';
    const TBL_PERSON_LAST_NAME_S2 = 'TblPerson_LastName_S2';
    const TBL_PERSON_BIRTH_NAME_S2 = 'TblPerson_BirthName_S2';
    const TBL_ADDRESS_STREET_NAME_S2 = 'TblAddress_StreetName_S2';
    const TBL_ADDRESS_STREET_NUMBER_S2 = 'TblAddress_StreetNumber_S2';
    const TBL_CITY_CODE_S2 = 'TblCity_Code_S2';
    const TBL_CITY_CITY_S2 = 'TblCity_City_S2';
    const TBL_CITY_DISTRICT_S2 = 'TblCity_District_S2';
    const TBL_ADDRESS_COUNTY_S2 = 'TblAddress_County_S2';
    const TBL_ADDRESS_STATE_S2 = 'TblState_Name_S2';
    const TBL_ADDRESS_NATION_S2 = 'TblAddress_Nation_S2';
    const TBL_PHONE_NUMBER_S2 = 'TblPhone_Number_S2';
    const TBL_MAIL_ADDRESS_S2 = 'TblMail_Address_S2';

    // S3
    const TBL_SALUTATION_SALUTATION_S3 = 'TblSalutation_Salutation_S3';
    const TBL_PERSON_TITLE_S3 = 'TblPerson_Title_S3';
    const TBL_PERSON_FIRST_NAME_S3 = 'TblPerson_FirstName_S3';
    const TBL_PERSON_SECOND_NAME_S3 = 'TblPerson_SecondName_S3';
    const TBL_PERSON_LAST_NAME_S3 = 'TblPerson_LastName_S3';
    const TBL_PERSON_BIRTH_NAME_S3 = 'TblPerson_BirthName_S3';
    const TBL_ADDRESS_STREET_NAME_S3 = 'TblAddress_StreetName_S3';
    const TBL_ADDRESS_STREET_NUMBER_S3 = 'TblAddress_StreetNumber_S3';
    const TBL_CITY_CODE_S3 = 'TblCity_Code_S3';
    const TBL_CITY_CITY_S3 = 'TblCity_City_S3';
    const TBL_CITY_DISTRICT_S3 = 'TblCity_District_S3';
    const TBL_ADDRESS_COUNTY_S3 = 'TblAddress_County_S3';
    const TBL_ADDRESS_STATE_S3 = 'TblState_Name_S3';
    const TBL_ADDRESS_NATION_S3 = 'TblAddress_Nation_S3';
    const TBL_PHONE_NUMBER_S3 = 'TblPhone_Number_S3';
    const TBL_MAIL_ADDRESS_S3 = 'TblMail_Address_S3';

    /**
     * @return array
     */
    static function getConstants()
    {
        $oClass = new \ReflectionClass(__CLASS__);
        return $oClass->getConstants();
    }

    /**
     * @Column(type="string")
     */
    protected $TblPerson_Id;
    /**
     * @Column(type="string")
     */
    protected $Bildungsgang;
    /**
     * @Column(type="string")
     */
    protected $Schule;
//    /**
//     * @Column(type="string")
//     */
//    protected $Arbeitsgemeinschaft1;
//    /**
//     * @Column(type="string")
//     */
//    protected $Arbeitsgemeinschaft2;
//    /**
//     * @Column(type="string")
//     */
//    protected $Arbeitsgemeinschaft3;
    /**
     * @Column(type="string")
     */
    protected $Fremdsprache1;
    /**
     * @Column(type="string")
     */
    protected $Fremdsprache2;
    /**
     * @Column(type="string")
     */
    protected $Fremdsprache3;
    /**
     * @Column(type="string")
     */
    protected $Fremdsprache4;
//    /**
//     * @Column(type="string")
//     */
//    protected $Wahlfach1;
//    /**
//     * @Column(type="string")
//     */
//    protected $Wahlfach2;
//    /**
//     * @Column(type="string")
//     */
//    protected $Wahlfach3;
    /**
     * @Column(type="string")
     */
    protected $Religion;
    /**
     * @Column(type="string")
     */
    protected $Profil;
    /**
     * @Column(type="string")
     */
    protected $Neigungskurs;
//    /**
//     * @Column(type="string")
//     */
//    protected $Befreiungen;

    /**
     * @Column(type="string")
     */
    protected $TblStudentMedicalRecord_Insurance;
    /**
     * @Column(type="string")
     */
    protected $TblStudentMedicalRecord_Disease;
    /**
     * @Column(type="string")
     */
    protected $TblStudentMedicalRecord_Medication;
    /**
     * @Column(type="string")
     */
    protected $TblStudentLocker_KeyNumber;
    /**
     * @Column(type="string")
     */
    protected $TblStudentLocker_LockerNumber;
    /**
     * @Column(type="string")
     */
    protected $TblStudent_Identifier;
    /**
     * @Column(type="string")
     */
    protected $Sibling_Count;

    /**
     * @Column(type="string")
     */
    protected $TblSalutation_Salutation_S1;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_Title_S1;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_FirstName_S1;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_SecondName_S1;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_LastName_S1;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_BirthName_S1;
    /**
     * @Column(type="string")
     */
    protected $TblAddress_StreetName_S1;
    /**
     * @Column(type="string")
     */
    protected $TblAddress_StreetNumber_S1;
    /**
     * @Column(type="string")
     */
    protected $TblCity_Code_S1;
    /**
     * @Column(type="string")
     */
    protected $TblCity_City_S1;
    /**
     * @Column(type="string")
     */
    protected $TblCity_District_S1;
    /**
     * @Column(type="string")
     */
    protected $TblAddress_County_S1;
    /**
     * @Column(type="string")
     */
    protected $TblState_Name_S1;
    /**
     * @Column(type="string")
     */
    protected $TblAddress_Nation_S1;
    /**
     * @Column(type="string")
     */
    protected $TblPhone_Number_S1;
    /**
     * @Column(type="string")
     */
    protected $TblMail_Address_S1;

    /**
     * @Column(type="string")
     */
    protected $TblSalutation_Salutation_S2;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_Title_S2;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_FirstName_S2;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_SecondName_S2;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_LastName_S2;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_BirthName_S2;
    /**
     * @Column(type="string")
     */
    protected $TblAddress_StreetName_S2;
    /**
     * @Column(type="string")
     */
    protected $TblAddress_StreetNumber_S2;
    /**
     * @Column(type="string")
     */
    protected $TblCity_Code_S2;
    /**
     * @Column(type="string")
     */
    protected $TblCity_City_S2;
    /**
     * @Column(type="string")
     */
    protected $TblCity_District_S2;
    /**
     * @Column(type="string")
     */
    protected $TblAddress_County_S2;
    /**
     * @Column(type="string")
     */
    protected $TblState_Name_S2;
    /**
     * @Column(type="string")
     */
    protected $TblAddress_Nation_S2;
    /**
     * @Column(type="string")
     */
    protected $TblPhone_Number_S2;
    /**
     * @Column(type="string")
     */
    protected $TblMail_Address_S2;

    /**
     * @Column(type="string")
     */
    protected $TblSalutation_Salutation_S3;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_Title_S3;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_FirstName_S3;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_SecondName_S3;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_LastName_S3;
    /**
     * @Column(type="string")
     */
    protected $TblPerson_BirthName_S3;
    /**
     * @Column(type="string")
     */
    protected $TblAddress_StreetName_S3;
    /**
     * @Column(type="string")
     */
    protected $TblAddress_StreetNumber_S3;
    /**
     * @Column(type="string")
     */
    protected $TblCity_Code_S3;
    /**
     * @Column(type="string")
     */
    protected $TblCity_City_S3;
    /**
     * @Column(type="string")
     */
    protected $TblCity_District_S3;
    /**
     * @Column(type="string")
     */
    protected $TblAddress_County_S3;
    /**
     * @Column(type="string")
     */
    protected $TblState_Name_S3;
    /**
     * @Column(type="string")
     */
    protected $TblAddress_Nation_S3;
    /**
     * @Column(type="string")
     */
    protected $TblPhone_Number_S3;
    /**
     * @Column(type="string")
     */
    protected $TblMail_Address_S3;

    /**
     * Use this method to set PropertyName to DisplayName conversions with "setNameDefinition()"
     *
     * @return void
     */
    public function loadNameDefinition()
    {

//        //NameDefinition
        $this->setNameDefinition(self::TBL_STUDENT_IDENTIFIER, 'Schüler: Schülernummer');
        $this->setNameDefinition(self::SCHULE, 'Schüler: Aktuelle Schule');
        $this->setNameDefinition(self::BILDUNGSGANG, 'Schüler: Aktueller Bildungsgang');
        $this->setNameDefinition(self::TBL_STUDENT_MEDICAL_RECORD_DISEASE, 'Schüler: Krankheiten / Allergien');
        $this->setNameDefinition(self::TBL_STUDENT_MEDICAL_RECORD_MEDICATION, 'Schüler: Medikamente');
//        $this->setNameDefinition(self::ARBEITSGEMEINSCHAFT_1, 'Arbeitsgemeinschaft 1');
//        $this->setNameDefinition(self::ARBEITSGEMEINSCHAFT_2, 'Arbeitsgemeinschaft 2');
//        $this->setNameDefinition(self::ARBEITSGEMEINSCHAFT_3, 'Arbeitsgemeinschaft 3');
        $this->setNameDefinition(self::FREMDSPRACHE_1, 'Schüler: Fremdsprache 1');
        $this->setNameDefinition(self::FREMDSPRACHE_2, 'Schüler: Fremdsprache 2');
        $this->setNameDefinition(self::FREMDSPRACHE_3, 'Schüler: Fremdsprache 3');
        $this->setNameDefinition(self::FREMDSPRACHE_4, 'Schüler: Fremdsprache 4');
//        $this->setNameDefinition(self::WAHLFACH_1, 'Wahlfach 1');
//        $this->setNameDefinition(self::WAHLFACH_2, 'Wahlfach 2');
//        $this->setNameDefinition(self::WAHLFACH_3, 'Wahlfach 3');
        $this->setNameDefinition(self::RELIGION, 'Schüler: Religion');
        $this->setNameDefinition(self::PROFIL, 'Schüler: Profil');
        $this->setNameDefinition(self::NEIGUNGSKURS, 'Schüler: Neigungskurs');
//        $this->setNameDefinition(self::BEFREIUNGEN, 'Befreiungen');

        $this->setNameDefinition(self::TBL_STUDENT_MEDICAL_RECORD_INSURANCE, 'Schüler: Versicherung');
        $this->setNameDefinition(self::TBL_STUDENT_LOCKER_KEY_NUMBER, 'Schüler: Schließfach Schlüsselnummer');
        $this->setNameDefinition(self::TBL_STUDENT_LOCKER_LOCKER_NUMBER, 'Schüler: Schließfachnummer');
        $this->setNameDefinition(self::SIBLINGS_COUNT, 'Schüler: Anzahl Geschwister');
        // S1
        $this->setNameDefinition(self::TBL_SALUTATION_SALUTATION_S1, 'S1: Anrede');
        $this->setNameDefinition(self::TBL_PERSON_TITLE_S1, 'S1: Titel');
        $this->setNameDefinition(self::TBL_PERSON_FIRST_NAME_S1, 'S1: Vorname');
        $this->setNameDefinition(self::TBL_PERSON_SECOND_NAME_S1, 'S1: Zweiter Vorname');
        $this->setNameDefinition(self::TBL_PERSON_LAST_NAME_S1, 'S1: Nachname');
        $this->setNameDefinition(self::TBL_PERSON_BIRTH_NAME_S1, 'S1: Geburtsname');
        $this->setNameDefinition(self::TBL_ADDRESS_STREET_NAME_S1, 'S1: Straße');
        $this->setNameDefinition(self::TBL_ADDRESS_STREET_NUMBER_S1, 'S1: Hausnummer');
        $this->setNameDefinition(self::TBL_CITY_CODE_S1, 'S1: PLZ');
        $this->setNameDefinition(self::TBL_CITY_CITY_S1, 'S1: Ort');
        $this->setNameDefinition(self::TBL_CITY_DISTRICT_S1, 'S1: Ortsteil');
        $this->setNameDefinition(self::TBL_ADDRESS_COUNTY_S1, 'S1: Landkreis');
        $this->setNameDefinition(self::TBL_ADDRESS_STATE_S1, 'S1: Bundesland');
        $this->setNameDefinition(self::TBL_ADDRESS_NATION_S1, 'S1: Land');
        $this->setNameDefinition(self::TBL_PHONE_NUMBER_S1, 'S1: Telefon');
        $this->setNameDefinition(self::TBL_MAIL_ADDRESS_S1, 'S1: E-Mail');
        // S2
        $this->setNameDefinition(self::TBL_SALUTATION_SALUTATION_S2, 'S2: Anrede');
        $this->setNameDefinition(self::TBL_PERSON_TITLE_S2, 'S2: Titel');
        $this->setNameDefinition(self::TBL_PERSON_FIRST_NAME_S2, 'S2: Vorname');
        $this->setNameDefinition(self::TBL_PERSON_SECOND_NAME_S2, 'S2: Zweiter Vorname');
        $this->setNameDefinition(self::TBL_PERSON_LAST_NAME_S2, 'S2: Nachname');
        $this->setNameDefinition(self::TBL_PERSON_BIRTH_NAME_S2, 'S2: Geburtsname');
        $this->setNameDefinition(self::TBL_ADDRESS_STREET_NAME_S2, 'S2: Straße');
        $this->setNameDefinition(self::TBL_ADDRESS_STREET_NUMBER_S2, 'S2: Hausnummer');
        $this->setNameDefinition(self::TBL_CITY_CODE_S2, 'S2: PLZ');
        $this->setNameDefinition(self::TBL_CITY_CITY_S2, 'S2: Ort');
        $this->setNameDefinition(self::TBL_CITY_DISTRICT_S2, 'S2: Ortsteil');
        $this->setNameDefinition(self::TBL_ADDRESS_COUNTY_S2, 'S2: Landkreis');
        $this->setNameDefinition(self::TBL_ADDRESS_STATE_S2, 'S2: Bundesland');
        $this->setNameDefinition(self::TBL_ADDRESS_NATION_S2, 'S2: Land');
        $this->setNameDefinition(self::TBL_PHONE_NUMBER_S2, 'S2: Telefon');
        $this->setNameDefinition(self::TBL_MAIL_ADDRESS_S2, 'S2: E-Mail');
        // S3
        $this->setNameDefinition(self::TBL_SALUTATION_SALUTATION_S3, 'S3: Anrede');
        $this->setNameDefinition(self::TBL_PERSON_TITLE_S3, 'S3: Titel');
        $this->setNameDefinition(self::TBL_PERSON_FIRST_NAME_S3, 'S3: Vorname');
        $this->setNameDefinition(self::TBL_PERSON_SECOND_NAME_S3, 'S3: Zweiter Vorname');
        $this->setNameDefinition(self::TBL_PERSON_LAST_NAME_S3, 'S3: Nachname');
        $this->setNameDefinition(self::TBL_PERSON_BIRTH_NAME_S3, 'S3: Geburtsname');
        $this->setNameDefinition(self::TBL_ADDRESS_STREET_NAME_S3, 'S3: Straße');
        $this->setNameDefinition(self::TBL_ADDRESS_STREET_NUMBER_S3, 'S3: Hausnummer');
        $this->setNameDefinition(self::TBL_CITY_CODE_S3, 'S3: PLZ');
        $this->setNameDefinition(self::TBL_CITY_CITY_S3, 'S3: Ort');
        $this->setNameDefinition(self::TBL_CITY_DISTRICT_S3, 'S3: Ortsteil');
        $this->setNameDefinition(self::TBL_ADDRESS_COUNTY_S3, 'S3: Landkreis');
        $this->setNameDefinition(self::TBL_ADDRESS_STATE_S3, 'S3: Bundesland');
        $this->setNameDefinition(self::TBL_ADDRESS_NATION_S3, 'S3: Land');
        $this->setNameDefinition(self::TBL_PHONE_NUMBER_S3, 'S3: Telefon');
        $this->setNameDefinition(self::TBL_MAIL_ADDRESS_S3, 'S3: E-Mail');

//        //GroupDefinition
        $this->setGroupDefinition('Schülerakte', array(
            self::TBL_STUDENT_IDENTIFIER,
            self::SCHULE,
            self::BILDUNGSGANG,
            self::TBL_STUDENT_MEDICAL_RECORD_DISEASE,
            self::TBL_STUDENT_MEDICAL_RECORD_MEDICATION,
//            self::ARBEITSGEMEINSCHAFT_1,
//            self::ARBEITSGEMEINSCHAFT_2,
//            self::ARBEITSGEMEINSCHAFT_3,
            self::FREMDSPRACHE_1,
            self::FREMDSPRACHE_2,
            self::FREMDSPRACHE_3,
            self::FREMDSPRACHE_4,
//            self::WAHLFACH_1,
//            self::WAHLFACH_2,
//            self::WAHLFACH_3,
            self::RELIGION,
            self::PROFIL,
            self::NEIGUNGSKURS,
//            self::BEFREIUNGEN,
//            self::TBL_STUDENT_MEDICAL_RECORD_INSURANCE,
//            self::TBL_STUDENT_LOCKER_KEY_NUMBER,
//            self::TBL_STUDENT_LOCKER_LOCKER_NUMBER,
//            self::SIBLINGS_COUNT
        ));

        $this->setGroupDefinition('Sorge. S1 (Zusatzinfo)', array(
            self::TBL_SALUTATION_SALUTATION_S1,
            self::TBL_PERSON_TITLE_S1,
            self::TBL_PERSON_FIRST_NAME_S1,
            self::TBL_PERSON_SECOND_NAME_S1,
            self::TBL_PERSON_LAST_NAME_S1,
            self::TBL_PERSON_BIRTH_NAME_S1,
            self::TBL_ADDRESS_STREET_NAME_S1,
            self::TBL_ADDRESS_STREET_NUMBER_S1,
            self::TBL_CITY_CODE_S1,
            self::TBL_CITY_CITY_S1,
            self::TBL_CITY_DISTRICT_S1,
            self::TBL_ADDRESS_COUNTY_S1,
            self::TBL_ADDRESS_STATE_S1,
            self::TBL_ADDRESS_NATION_S1,
            self::TBL_PHONE_NUMBER_S1,
            self::TBL_MAIL_ADDRESS_S1
        ));
        $this->setGroupDefinition('Sorge. S2 (Zusatzinfo)', array(
            self::TBL_SALUTATION_SALUTATION_S2,
            self::TBL_PERSON_TITLE_S2,
            self::TBL_PERSON_FIRST_NAME_S2,
            self::TBL_PERSON_SECOND_NAME_S2,
            self::TBL_PERSON_LAST_NAME_S2,
            self::TBL_PERSON_BIRTH_NAME_S2,
            self::TBL_ADDRESS_STREET_NAME_S2,
            self::TBL_ADDRESS_STREET_NUMBER_S2,
            self::TBL_CITY_CODE_S2,
            self::TBL_CITY_CITY_S2,
            self::TBL_CITY_DISTRICT_S2,
            self::TBL_ADDRESS_COUNTY_S2,
            self::TBL_ADDRESS_STATE_S2,
            self::TBL_ADDRESS_NATION_S2,
            self::TBL_PHONE_NUMBER_S2,
            self::TBL_MAIL_ADDRESS_S2
        ));
        $this->setGroupDefinition('Sorge. S3 (Zusatzinfo)', array(
            self::TBL_SALUTATION_SALUTATION_S3,
            self::TBL_PERSON_TITLE_S3,
            self::TBL_PERSON_FIRST_NAME_S3,
            self::TBL_PERSON_SECOND_NAME_S3,
            self::TBL_PERSON_LAST_NAME_S3,
            self::TBL_PERSON_BIRTH_NAME_S3,
            self::TBL_ADDRESS_STREET_NAME_S3,
            self::TBL_ADDRESS_STREET_NUMBER_S3,
            self::TBL_CITY_CODE_S3,
            self::TBL_CITY_CITY_S3,
            self::TBL_CITY_DISTRICT_S3,
            self::TBL_ADDRESS_COUNTY_S3,
            self::TBL_ADDRESS_STATE_S3,
            self::TBL_ADDRESS_NATION_S3,
            self::TBL_PHONE_NUMBER_S3,
            self::TBL_MAIL_ADDRESS_S3,
        ));

        // Flag um Filter zu deaktivieren (nur Anzeige von Informationen)
        $this->setDisableDefinition(self::TBL_SALUTATION_SALUTATION_S1);
        $this->setDisableDefinition(self::TBL_PERSON_TITLE_S1);
        $this->setDisableDefinition(self::TBL_PERSON_FIRST_NAME_S1);
        $this->setDisableDefinition(self::TBL_PERSON_SECOND_NAME_S1);
        $this->setDisableDefinition(self::TBL_PERSON_LAST_NAME_S1);
        $this->setDisableDefinition(self::TBL_PERSON_BIRTH_NAME_S1);
        $this->setDisableDefinition(self::TBL_ADDRESS_STREET_NAME_S1);
        $this->setDisableDefinition(self::TBL_ADDRESS_STREET_NUMBER_S1);
        $this->setDisableDefinition(self::TBL_CITY_CODE_S1);
        $this->setDisableDefinition(self::TBL_CITY_CITY_S1);
        $this->setDisableDefinition(self::TBL_CITY_DISTRICT_S1);
        $this->setDisableDefinition(self::TBL_ADDRESS_COUNTY_S1);
        $this->setDisableDefinition(self::TBL_ADDRESS_STATE_S1);
        $this->setDisableDefinition(self::TBL_ADDRESS_NATION_S1);
        $this->setDisableDefinition(self::TBL_PHONE_NUMBER_S1);
        $this->setDisableDefinition(self::TBL_MAIL_ADDRESS_S1);
        $this->setDisableDefinition(self::TBL_SALUTATION_SALUTATION_S2);
        $this->setDisableDefinition(self::TBL_PERSON_TITLE_S2);
        $this->setDisableDefinition(self::TBL_PERSON_FIRST_NAME_S2);
        $this->setDisableDefinition(self::TBL_PERSON_SECOND_NAME_S2);
        $this->setDisableDefinition(self::TBL_PERSON_LAST_NAME_S2);
        $this->setDisableDefinition(self::TBL_PERSON_BIRTH_NAME_S2);
        $this->setDisableDefinition(self::TBL_ADDRESS_STREET_NAME_S2);
        $this->setDisableDefinition(self::TBL_ADDRESS_STREET_NUMBER_S2);
        $this->setDisableDefinition(self::TBL_CITY_CODE_S2);
        $this->setDisableDefinition(self::TBL_CITY_CITY_S2);
        $this->setDisableDefinition(self::TBL_CITY_DISTRICT_S2);
        $this->setDisableDefinition(self::TBL_ADDRESS_COUNTY_S2);
        $this->setDisableDefinition(self::TBL_ADDRESS_STATE_S2);
        $this->setDisableDefinition(self::TBL_ADDRESS_NATION_S2);
        $this->setDisableDefinition(self::TBL_PHONE_NUMBER_S2);
        $this->setDisableDefinition(self::TBL_MAIL_ADDRESS_S2);
        $this->setDisableDefinition(self::TBL_SALUTATION_SALUTATION_S3);
        $this->setDisableDefinition(self::TBL_PERSON_TITLE_S3);
        $this->setDisableDefinition(self::TBL_PERSON_FIRST_NAME_S3);
        $this->setDisableDefinition(self::TBL_PERSON_SECOND_NAME_S3);
        $this->setDisableDefinition(self::TBL_PERSON_LAST_NAME_S3);
        $this->setDisableDefinition(self::TBL_PERSON_BIRTH_NAME_S3);
        $this->setDisableDefinition(self::TBL_ADDRESS_STREET_NAME_S3);
        $this->setDisableDefinition(self::TBL_ADDRESS_STREET_NUMBER_S3);
        $this->setDisableDefinition(self::TBL_CITY_CODE_S3);
        $this->setDisableDefinition(self::TBL_CITY_CITY_S3);
        $this->setDisableDefinition(self::TBL_CITY_DISTRICT_S3);
        $this->setDisableDefinition(self::TBL_ADDRESS_COUNTY_S3);
        $this->setDisableDefinition(self::TBL_ADDRESS_STATE_S3);
        $this->setDisableDefinition(self::TBL_ADDRESS_NATION_S3);
        $this->setDisableDefinition(self::TBL_PHONE_NUMBER_S3);
        $this->setDisableDefinition(self::TBL_MAIL_ADDRESS_S3);
    }

    /**
     * Use this method to add ForeignViews to Graph with "addForeignView()"
     *
     * @return void
     */
    public function loadViewGraph()
    {
        // TODO: Implement loadViewGraph() method.
    }

    /**
     * @return void|AbstractService
     */
    public function getViewService()
    {
        // TODO: Implement getViewService() method.
    }

    /**
     * Define Property Field-Type and additional Data
     *
     * @param string $PropertyName __CLASS__::{CONSTANT_}
     * @param null|string $Placeholder
     * @param null|string $Label
     * @param IIconInterface|null $Icon
     * @param bool $doResetCount Reset ALL FieldName calculations e.g. FieldName[23] -> FieldName[1]
     * @return AbstractField
     */
    public function getFormField( $PropertyName, $Placeholder = null, $Label = null, IIconInterface $Icon = null, $doResetCount = false )
    {

        switch ($PropertyName) {
            case self::SIBLINGS_COUNT:
                $PropertyCount = $this->calculateFormFieldCount( $PropertyName, $doResetCount );
                $Field = new NumberField( $PropertyName.'['.$PropertyCount.']',
                    $Placeholder, $Label, $Icon
                );
                break;
            case self::BILDUNGSGANG:
                $Data = Course::useService()->getPropertyList( new TblCourse(), TblCourse::ATTR_NAME );
                $Field = $this->getFormFieldSelectBox( $Data, $PropertyName, $Label, $Icon, $doResetCount );
                break;
            default:
                $Field = parent::getFormField( $PropertyName, $Placeholder, $Label, ($Icon?$Icon:new Pencil()), $doResetCount );
                break;
        }
        return $Field;
    }

}
