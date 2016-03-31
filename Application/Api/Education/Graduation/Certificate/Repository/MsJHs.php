<?php
namespace SPHERE\Application\Api\Education\Graduation\Certificate\Repository;

use SPHERE\Application\Api\Education\Graduation\Certificate\Certificate;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Document;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Element;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Frame;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Page;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Section;
use SPHERE\Application\Education\Graduation\Certificate\Repository\Slice;
use SPHERE\Common\Frontend\Layout\Repository\Container;

class MsJHs extends Certificate
{

    /**
     * @return Frame
     */
    public function buildCertificate()
    {

        $Header = (new Slice())
            ->addSection((new Section())
                ->addElementColumn((new Element())
                    ->setContent('MS Jahreszeugnis Hauptschule 3c.pdf')
                    ->styleTextSize('12px')
                    ->styleTextColor('#CCC')
                    ->styleAlignCenter()
                    , '25%')
                ->addElementColumn((new Element\Sample())
                    ->styleTextSize('30px')
                )
                ->addElementColumn((new Element\Image('/Common/Style/Resource/Logo/ClaimFreistaatSachsen.jpg', '200px'))
                    , '25%')
            );

        return (new Frame())->addDocument((new Document())
            ->addPage((new Page())
                ->addSlice(
                    $Header
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Name der Schule:')
                            , '18%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Company.Data.Name is not empty) %}
                                    {{ Content.Company.Data.Name }}
                                {% else %}
                                    &nbsp;
                                {% endif %}
                            ')
                            ->styleBorderBottom()
                            , '82%')
                    )->styleMarginTop('20px')
                )
                ->addSlice((new Slice())
                    ->addElement((new Element())
                        ->setContent('Jahreszeugnis der Mittelschule')
                        ->styleTextSize('18px')
                        ->styleTextBold()
                        ->styleAlignCenter()
                        ->styleMarginTop('15px')
                    )
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Klasse:')
                            , '7%')
                        ->addElementColumn((new Element())
                            ->setContent('{{ Content.Division.Data.Level.Name }}{{ Content.Division.Data.Name }}')
                            ->styleBorderBottom()
                            ->styleAlignCenter()
                            , '7%')
                        ->addElementColumn((new Element())
                            , '55%')
                        ->addElementColumn((new Element())
                            ->setContent('Schuljahr:')
                            ->styleAlignRight()
                            , '18%')
                        ->addElementColumn((new Element())
                            ->setContent('2015/16')
                            ->styleBorderBottom()
                            ->styleAlignCenter()
                            , '13%')
                    )->styleMarginTop('20px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Vorname und Name:')
                            , '21%')
                        ->addElementColumn((new Element())
                            ->setContent('{{ Content.Person.Data.Name.First }}
                                          {{ Content.Person.Data.Name.Last }}')
                            ->styleBorderBottom()
                            , '79%')
                    )->styleMarginTop('5px')
                )
                ->addSlice((new Slice())
                    ->addElement((new Element())
                        ->setContent('nahm am Unterricht mit dem Ziel des Hauptschulabschlusses teil.')
                        ->styleTextSize('11px')
                        ->styleMarginTop('7px')
                    )->styleMarginTop('5px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Betragen')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.ToDO is not empty) %}
                                                {{ Content.Grade.Data.ToDO }}
                                            {% else %}
                                                ---
                                            {% endif %}')//ToDO Kopfnoten
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                        ->addElementColumn((new Element())
                            , '4%')
                        ->addElementColumn((new Element())
                            ->setContent('Mitarbeit')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.ToDO is not empty) %}
                                                {{ Content.Grade.Data.ToDO }}
                                            {% else %}
                                                ---
                                            {% endif %}')//ToDO Kopfnoten
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                    )
                    ->styleMarginTop('15px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Fleiß')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.ToDO is not empty) %}
                                                {{ Content.Grade.Data.ToDO }}
                                            {% else %}
                                                ---
                                            {% endif %}')//ToDO Kopfnoten
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                        ->addElementColumn((new Element())
                            , '4%')
                        ->addElementColumn((new Element())
                            ->setContent('Ordnung')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.ToDO is not empty) %}
                                                {{ Content.Grade.Data.ToDO }}
                                            {% else %}
                                                ---
                                            {% endif %}')//ToDO Kopfnoten
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                    )
                    ->styleMarginTop('3px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Einschätzung:')
                            , '16%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Input.Rating is not empty) %}
                                    {{ Content.Input.Rating|nl2br }}
                                {% else %}
                                    &nbsp;
                                {% endif %}')
                            ->styleBorderBottom('1px', '#BBB')
                            , '84%')
                    )
                    ->styleMarginTop('15px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('&nbsp;')
                            ->styleBorderBottom('1px', '#BBB')
                        )
                    )
                    ->styleMarginTop('5px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('&nbsp;')
                            ->styleBorderBottom('1px', '#BBB')
                        )
                    )
                    ->styleMarginTop('5px')
                )
                ->addSlice((new Slice())
                    ->addElement((new Element())
                        ->setContent('Leistungen in den einzelnen Fächern:')
                        ->styleMarginTop('15px')
                        ->styleTextBold()
                    )
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Deutsch')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.DE is not empty) %}
                                    {{ Content.Grade.Data.DE }}
                                {% else %}
                                    ---
                                {% endif %}')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                        ->addElementColumn((new Element())
                            , '4%')
                        ->addElementColumn((new Element())
                            ->setContent('Mathematik')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.MA is not empty) %}
                                    {{ Content.Grade.Data.MA }}
                                {% else %}
                                    ---
                                {% endif %}')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                    )
                    ->styleMarginTop('5px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Englisch')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.EN is not empty) %}
                                    {{ Content.Grade.Data.EN }}
                                {% else %}
                                    ---
                                {% endif %}')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                        ->addElementColumn((new Element())
                            , '4%')
                        ->addElementColumn((new Element())
                            ->setContent('Biologie')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.BI is not empty) %}
                                    {{ Content.Grade.Data.BI }}
                                {% else %}
                                    ---
                                {% endif %}')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                    )
                    ->styleMarginTop('3px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Kunst')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.KU is not empty) %}
                                    {{ Content.Grade.Data.KU }}
                                {% else %}
                                    ---
                                {% endif %}')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                        ->addElementColumn((new Element())
                            , '4%')
                        ->addElementColumn((new Element())
                            ->setContent('Chemie')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.CH is not empty) %}
                                    {{ Content.Grade.Data.CH }}
                                {% else %}
                                    ---
                                {% endif %}')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                    )
                    ->styleMarginTop('3px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Musik')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.MU is not empty) %}
                                    {{ Content.Grade.Data.MU }}
                                {% else %}
                                    ---
                                {% endif %}')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                        ->addElementColumn((new Element())
                            , '4%')
                        ->addElementColumn((new Element())
                            ->setContent('Physik')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.PH is not empty) %}
                                    {{ Content.Grade.Data.PH }}
                                {% else %}
                                    ---
                                {% endif %}')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                    )
                    ->styleMarginTop('3px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Geschichte')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.GE is not empty) %}
                                    {{ Content.Grade.Data.GE }}
                                {% else %}
                                    ---
                                {% endif %}')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                        ->addElementColumn((new Element())
                            , '4%')
                        ->addElementColumn((new Element())
                            ->setContent('Sport')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.ToDO is not empty) %}
                                    {{ Content.Grade.Data.ToDO }}
                                {% else %}
                                    ---
                                {% endif %}')//ToDO Sport ist kein vorgegebenes Fach
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                    )
                    ->styleMarginTop('3px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Gemeinschaftskunde/Rechtserziehung')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.ToDO is not empty) %}
                                    {{ Content.Grade.Data.ToDO }}
                                {% else %}
                                    ---
                                {% endif %}')//ToDO Gemeinschaftskunde/Rechtserziehung ist kein vorgegebenes Fach
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                        ->addElementColumn((new Element())
                            , '4%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.ETH is not empty) %}
                                    Ethik
                                {% else %}
                                    {% if(Content.Grade.Data.RKA is not empty) %}
                                        Kath. Religion
                                    {% else %}
                                        {% if(Content.Grade.Data.REV is not empty) %}
                                            Ev. Religion
                                        {% else %}
                                            Ev./Kath. Religion/Ethik¹
                                        {% endif %}
                                    {% endif %}
                                {% endif %}')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.ETH is not empty) %}
                                    {{ Content.Grade.Data.ETH }}
                                {% else %}
                                    {% if(Content.Grade.Data.RKA is not empty) %}
                                        {{ Content.Grade.Data.RKA }}
                                    {% else %}
                                        {% if(Content.Grade.Data.REV is not empty) %}
                                        {{ Content.Grade.Data.REV }}
                                        {% else %}
                                            ---
                                        {% endif %}
                                    {% endif %}
                                {% endif %}')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                    )
                    ->styleMarginTop('3px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Geographie')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.GEO is not empty) %}
                                    {{ Content.Grade.Data.GEO }}
                                {% else %}
                                    ---
                                {% endif %}')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                        ->addElementColumn((new Element())
                            , '4%')
                        ->addElementColumn((new Element())
                            ->setContent('Technik/Computer')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())//ToDO Technik/Computer ist kein vorgegebenes Fach
                        ->setContent('{% if(Content.Grade.Data.GE is not empty) %}
                                    {{ Content.Grade.Data.GE }}
                                {% else %}
                                    ---
                                {% endif %}')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                    )
                    ->styleMarginTop('3px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Wirtschaft-Technik-Haushalt/Soziales')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.ToDO is not empty) %}
                                    {{ Content.Grade.Data.ToDO }}
                                {% else %}
                                    ---
                                {% endif %}')//ToDO Wirtschaft-Technik-Haushalt/Soziales
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                        ->addElementColumn((new Element())
                            , '4%')
                        ->addElementColumn((new Element())
                            ->setContent('Informatik')
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Grade.Data.IN is not empty) %}
                                    {{ Content.Grade.Data.IN }}
                                {% else %}
                                    ---
                                {% endif %}')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                    )
                    ->styleMarginTop('3px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->styleMarginTop('16px')
                            ->styleBorderBottom()
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('&nbsp;')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                        ->addElementColumn((new Element())
                            , '4%')
                        ->addElementColumn((new Element())
                            ->styleMarginTop('16px')
                            ->styleBorderBottom()
                            ->stylePaddingTop()
                            , '39%')
                        ->addElementColumn((new Element())
                            ->setContent('&nbsp;')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            ->stylePaddingTop()
                            ->stylePaddingBottom()
                            , '9%')
                    )
                    ->styleMarginTop('3px')
                )
                ->addSlice((new Slice())
                    ->addElement((new Element())
                        ->setContent('Wahlpflichtbereich:')
                        ->styleMarginTop('15px')
                        ->styleTextBold()
                    )
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Person.Data.ToDO is not empty) %}
                                    {{ Content.Grade.Data.ToDO }} Vertiefungskurs
                                {% else %}
                                    {% if(Content.Person.Data.ToDO is not empty) %}
                                        {{ Content.Grade.Data.ToDO }} 2. Fremdsprache (abschlussorientiert)
                                    {% else %}
                                        &nbsp;
                                    {% endif %}
                                {% endif %}')//ToDO Wahlpflichtbereich
                            ->styleBorderBottom()
                        )
                        ->addElementColumn((new Element())
                            ->setContent('&nbsp;')
                            ->styleAlignCenter()
                            ->styleBackgroundColor('#BBB')
                            ->styleBorderBottom('1px', '#000')
                            , '9%')
                    )
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Person.Data.ToDO is not empty) %}
                                    Vertiefungskurs
                                {% else %}
                                    {% if(Content.Person.Data.ToDO is not empty) %}
                                        2. Fremdsprache (abschlussorientiert)
                                    {% else %}
                                        &nbsp;
                                    {% endif %}
                                {% endif %}')//ToDO Wahlpflichtbereich
                            ->styleTextSize('11px')
                        )
                    )
                    ->styleMarginTop('5px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Bemerkungen:')
                            , '16%')
                        ->addElementColumn((new Element())
                            ->setContent('Fehltage entschuldigt:')
                            ->styleBorderBottom('1px', '#BBB')
                            ->styleAlignRight()
                            , '25%')
                        ->addElementColumn((new Element())
                            ->setContent('&nbsp;')
                            ->styleBorderBottom('1px', '#BBB')
                            ->styleAlignCenter()
                            , '10%')
                        ->addElementColumn((new Element())
                            ->setContent('unentschuldigt:')
                            ->styleBorderBottom('1px', '#BBB')
                            ->styleAlignRight()
                            , '25%')
                        ->addElementColumn((new Element())
                            ->setContent('&nbsp;')
                            ->styleBorderBottom('1px', '#BBB')
                            ->styleAlignCenter()
                            , '10%')
                        ->addElementColumn((new Element())
                            ->setContent('&nbsp;')
                            ->styleBorderBottom('1px', '#BBB')
                            ->styleAlignCenter()
                            , '4%')
                    )
                    ->styleMarginTop('15px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Input.Remark is not empty) %}
                                    {{ Content.Input.Remark|nl2br }}
                                {% else %}
                                    &nbsp;
                                {% endif %}')
                            ->styleBorderBottom('1px', '#BBB')
                        )
                    )
                    ->styleMarginTop('5px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('&nbsp;')
                            ->styleBorderBottom('1px', '#BBB')
                        )
                    )
                    ->styleMarginTop('5px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Versetzungsvermerk:')
                            , '22%')
                        ->addElementColumn((new Element())
                            ->setContent('&nbsp;')
                            ->styleBorderBottom('1px', '#BBB')
                            , '58%')
                        ->addElementColumn((new Element())
                            , '20%')
                    )
                    ->styleMarginTop('5px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Datum:')
                            , '7%')
                        ->addElementColumn((new Element())
                            ->setContent('{% if(Content.Input.Date is not empty) %}
                                    {{ Content.Input.Date }}
                                {% else %}
                                    &nbsp;
                                {% endif %}')
                            ->styleBorderBottom('1px', '#000')
                            ->styleAlignCenter()
                            , '23%')
                        ->addElementColumn((new Element())
                            , '5%')
                        ->addElementColumn((new Element())
                            , '30%')
                        ->addElementColumn((new Element())
                            , '5%')
                        ->addElementColumn((new Element())
                            , '30%')
                    )
                    ->styleMarginTop('30px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('&nbsp;')
                            ->styleAlignCenter()
                            ->styleBorderBottom('1px', '#000')
                            , '30%')
                        ->addElementColumn((new Element())
                            , '40%')
                        ->addElementColumn((new Element())
                            ->setContent('&nbsp;')
                            ->styleAlignCenter()
                            ->styleBorderBottom('1px', '#000')
                            , '30%')
                    )
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Schulleiter(in)')
                            ->styleAlignCenter()
                            ->styleTextSize('11px')
                            , '30%')
                        ->addElementColumn((new Element())
                            , '5%')
                        ->addElementColumn((new Element())
                            ->setContent('Dienstsiegel der Schule')
                            ->styleAlignCenter()
                            ->styleTextSize('11px')
                            , '30%')
                        ->addElementColumn((new Element())
                            , '5%')
                        ->addElementColumn((new Element())
                            ->setContent('Klassenlehrer(in)')
                            ->styleAlignCenter()
                            ->styleTextSize('11px')
                            , '30%')
                    )
                    ->styleMarginTop('30px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Zur Kenntnis genommen:')
                            , '30%')
                        ->addElementColumn((new Element())
                            ->setContent('&nbsp')
                            ->styleBorderBottom()
                            , '40px')
                        ->addElementColumn((new Element())
                            , '30%')
                    )
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            , '30%')
                        ->addElementColumn((new Element())
                            ->setContent('Eltern')
                            ->styleAlignCenter()
                            ->styleTextSize('11px')
                            , '40px')
                        ->addElementColumn((new Element())
                            , '30%')
                    )->styleMarginTop('30px')
                )
                ->addSlice((new Slice())
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->styleBorderBottom()
                            , '30%')
                        ->addElementColumn((new Element())
                            , '70%')
                    )->styleMarginTop('17px')
                    ->addSection((new Section())
                        ->addElementColumn((new Element())
                            ->setContent('Notenerläuterung:'
                                .new Container('1 = sehr gut; 2 = gut; 3 = befriedigend; 4 = ausreichend; 5 = mangelhaft;
                                          6 = ungenügend (6 = ungenügend nur bei der Bewertung der Leistungen)'))
                            ->styleTextSize('9.5px')
                            , '30%')
                    )
                )
            )
        );
    }
}